"""Deterministic quality gates for a proposed git diff.

The model's review is one input to this module, not an authority.  Every gate
here is local, reproducible, and represented in the returned ``QualityReport``.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import CommandResult, CriticReview, GateResult, QualityReport

_DEPENDENCY_FILES = {
    "build.sbt",
    "cargo.toml",
    "composer.json",
    "deno.json",
    "deno.jsonc",
    "deps.edn",
    "directory.packages.props",
    "gemfile",
    "go.mod",
    "go.work",
    "mix.exs",
    "package.json",
    "packages.config",
    "pipfile",
    "podfile",
    "pom.xml",
    "pubspec.yaml",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
}
_LOCK_FILES = {
    "bun.lock",
    "bun.lockb",
    "cargo.lock",
    "composer.lock",
    "deno.lock",
    "flake.lock",
    "gemfile.lock",
    "go.sum",
    "go.work.sum",
    "gradle.lockfile",
    "mix.lock",
    "package-lock.json",
    "package.resolved",
    "packages.lock.json",
    "paket.lock",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "podfile.lock",
    "poetry.lock",
    "pubspec.lock",
    "renv.lock",
    "uv.lock",
    "yarn.lock",
}
_WORKFLOW_FILES = {
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    "jenkinsfile",
}

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private key",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    (
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b"),
    ),
    (
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
)
_GENERIC_SECRET = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9_./+=-]{16,})"
)
_OBVIOUS_PLACEHOLDER = re.compile(
    r"(?i)(?:example|dummy|placeholder|change[-_]?me|test|fake|your[-_]?|x{4,})"
)


@dataclass
class _DiffFile:
    old_path: str
    new_path: str
    additions: int = 0
    deletions: int = 0
    binary: bool = False
    symlink: bool = False
    submodule: bool = False
    mode_changed: bool = False
    added_lines: list[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path if self.new_path != "/dev/null" else self.old_path

    @property
    def changed_lines(self) -> int:
        return self.additions + self.deletions


class QualityEvaluator:
    """Evaluate non-negotiable local gates for one candidate patch."""

    def __init__(self, config: AutocontributeConfig) -> None:
        self.config = config

    def evaluate(
        self,
        *,
        diff: str,
        command_results: Sequence[CommandResult],
        review: CriticReview,
        baseline_result: CommandResult | None = None,
        contribution_kind: str | None = None,
    ) -> QualityReport:
        files = _parse_git_diff(diff)
        paths = [item.path for item in files]
        changed_lines = sum(item.changed_lines for item in files)
        gates: list[GateResult] = []

        def gate(name: str, passed: bool, evidence: str) -> None:
            gates.append(GateResult(gate=name, passed=passed, evidence=evidence))

        gate(
            "diff_present",
            bool(files),
            f"parsed {len(files)} changed file(s) from the git diff",
        )
        file_limit = self.config.quality.max_files_changed
        gate(
            "file_count",
            0 < len(files) <= file_limit,
            f"{len(files)} changed file(s); maximum is {file_limit}",
        )
        line_limit = self.config.quality.max_changed_lines
        gate(
            "changed_lines",
            0 < changed_lines <= line_limit,
            f"{changed_lines} added/deleted line(s); maximum is {line_limit}",
        )

        binary_paths = [item.path for item in files if item.binary]
        gate(
            "no_binary_files",
            not binary_paths,
            _path_evidence("binary file", binary_paths),
        )
        symlink_paths = [item.path for item in files if item.symlink]
        gate(
            "no_symlinks",
            not symlink_paths,
            _path_evidence("symlink", symlink_paths),
        )
        submodule_paths = [item.path for item in files if item.submodule]
        gate(
            "no_submodules",
            not submodule_paths,
            _path_evidence("submodule", submodule_paths),
        )
        mode_paths = [item.path for item in files if item.mode_changed]
        gate(
            "no_mode_changes",
            not mode_paths,
            _path_evidence("mode change", mode_paths),
        )

        unsafe_paths = [path for path in paths if not _safe_repository_path(path)]
        gate(
            "safe_paths",
            not unsafe_paths,
            _path_evidence("unsafe path", unsafe_paths),
        )
        forbidden_paths = [
            path
            for path in paths
            if any(_path_matches(path, pattern) for pattern in self.config.quality.forbidden_paths)
        ]
        gate(
            "forbidden_paths",
            not forbidden_paths,
            _path_evidence("configured forbidden path", forbidden_paths),
        )

        dependency_paths = [path for path in paths if _is_dependency_path(path)]
        dependency_allowed = self.config.policy.allow_dependency_changes
        gate(
            "dependency_policy",
            dependency_allowed or not dependency_paths,
            (
                "dependency changes are allowed by policy"
                if dependency_allowed
                else _path_evidence("dependency or lock file", dependency_paths)
            ),
        )
        workflow_paths = [path for path in paths if _is_workflow_path(path)]
        workflow_allowed = self.config.policy.allow_workflow_changes
        gate(
            "workflow_policy",
            workflow_allowed or not workflow_paths,
            (
                "workflow changes are allowed by policy"
                if workflow_allowed
                else _path_evidence("workflow file", workflow_paths)
            ),
        )

        secret_findings = _secret_findings(files)
        gate(
            "secret_scan",
            not secret_findings,
            (
                "no secret patterns detected in added lines"
                if not secret_findings
                else "secret pattern(s) detected (values redacted): " + ", ".join(secret_findings)
            ),
        )

        passed_commands = sum(result.passed for result in command_results)
        failed_indexes = [
            str(index) for index, result in enumerate(command_results, start=1) if not result.passed
        ]
        validation_required = self.config.quality.require_validation_commands
        validation_ok = bool(command_results) or not validation_required
        validation_ok = validation_ok and passed_commands == len(command_results)
        validation_evidence = (
            f"{passed_commands}/{len(command_results)} validation command(s) passed"
        )
        if failed_indexes:
            validation_evidence += f"; failed command index(es): {', '.join(failed_indexes)}"
        elif not command_results and validation_required:
            validation_evidence += "; at least one command is required"
        gate("validation", validation_ok, validation_evidence)

        if (
            self.config.quality.require_regression_evidence_for_bugfix
            and contribution_kind == "bugfix"
        ):
            patched_reproduction = next(
                (
                    result
                    for result in command_results
                    if baseline_result is not None and result.command == baseline_result.command
                ),
                None,
            )
            regression_ok = (
                baseline_result is not None
                and not baseline_result.passed
                and patched_reproduction is not None
                and patched_reproduction.passed
            )
            gate(
                "regression_evidence",
                regression_ok,
                (
                    "same reproduction failed on pristine upstream and passed with the patch"
                    if regression_ok
                    else "bugfix lacks fail-on-base/pass-with-patch reproduction evidence"
                ),
            )

        gate(
            "critic_verdict",
            review.verdict == "approve",
            f"critic verdict: {review.verdict}",
        )
        gate(
            "critic_blockers",
            not review.blocking_findings,
            (
                "critic reported no blocking findings"
                if not review.blocking_findings
                else f"critic reported {len(review.blocking_findings)} blocking finding(s)"
            ),
        )
        gate(
            "issue_requirements",
            not review.issue_requirements_missing,
            (
                "critic reported no missing issue requirements"
                if not review.issue_requirements_missing
                else (
                    f"critic reported {len(review.issue_requirements_missing)} "
                    "missing requirement(s)"
                )
            ),
        )
        minimum_dimension = review.scores.minimum()
        required_dimension = self.config.quality.min_dimension_score
        gate(
            "minimum_review_dimension",
            minimum_dimension >= required_dimension,
            f"minimum critic dimension is {minimum_dimension}; required {required_dimension}",
        )
        readiness_score = review.scores.weighted_score()
        required_readiness = self.config.quality.min_readiness_score
        gate(
            "readiness_score",
            readiness_score >= required_readiness,
            f"weighted readiness is {readiness_score}; required {required_readiness}",
        )

        return QualityReport(
            ready=all(item.passed for item in gates),
            readiness_score=readiness_score,
            gates=gates,
            review=review,
            changed_files=len(files),
            changed_lines=changed_lines,
        )


def evaluate_quality(
    *,
    diff: str,
    command_results: Sequence[CommandResult],
    review: CriticReview,
    config: AutocontributeConfig,
    baseline_result: CommandResult | None = None,
    contribution_kind: str | None = None,
) -> QualityReport:
    """Convenience wrapper for callers that do not retain an evaluator."""

    return QualityEvaluator(config).evaluate(
        diff=diff,
        command_results=command_results,
        review=review,
        baseline_result=baseline_result,
        contribution_kind=contribution_kind,
    )


def _parse_git_diff(diff: str) -> list[_DiffFile]:
    files: list[_DiffFile] = []
    current: _DiffFile | None = None
    in_hunk = False

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if current is not None:
                files.append(current)
            paths = _header_paths(line)
            if paths is None:
                current = _DiffFile(old_path="<unparseable>", new_path="<unparseable>")
            else:
                current = _DiffFile(old_path=paths[0], new_path=paths[1])
            in_hunk = False
            continue
        if current is None:
            continue
        if line.startswith("@@"):
            in_hunk = True
        elif line.startswith("rename from "):
            current.old_path = _unquote_path(line.removeprefix("rename from "))
        elif line.startswith("rename to "):
            current.new_path = _unquote_path(line.removeprefix("rename to "))
        elif line.startswith("Binary files ") or line == "GIT binary patch":
            current.binary = True
        elif re.match(r"(?:old|new|new file|deleted file) mode 120000$", line):
            current.symlink = True
        elif re.match(r"(?:old|new|new file|deleted file) mode 160000$", line):
            current.submodule = True
        elif line.startswith("index ") and line.endswith(" 120000"):
            current.symlink = True
        elif line.startswith("index ") and line.endswith(" 160000"):
            current.submodule = True
        elif line.startswith("old mode ") or line.startswith("new mode "):
            current.mode_changed = True
        elif in_hunk and line.startswith("+"):
            current.additions += 1
            current.added_lines.append(line[1:])
        elif in_hunk and line.startswith("-"):
            current.deletions += 1

    if current is not None:
        files.append(current)
    return files


def _header_paths(line: str) -> tuple[str, str] | None:
    try:
        parts = shlex.split(line)
    except ValueError:
        return None
    if len(parts) != 4:
        return None
    return _strip_diff_prefix(parts[2]), _strip_diff_prefix(parts[3])


def _strip_diff_prefix(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


def _unquote_path(path: str) -> str:
    try:
        parts = shlex.split(path)
    except ValueError:
        return "<unparseable>"
    return parts[0] if len(parts) == 1 else path


def _safe_repository_path(path: str) -> bool:
    if not path or path in {"/dev/null", ".", "..", "<unparseable>"}:
        return False
    normalized = path.replace("\\", "/")
    if normalized.startswith("/") or "\x00" in normalized:
        return False
    return ".." not in normalized.split("/") and not any(ord(char) < 32 for char in normalized)


def _path_matches(path: str, pattern: str) -> bool:
    normalized_path = path.replace("\\", "/").removeprefix("./")
    normalized_pattern = pattern.replace("\\", "/").removeprefix("./")
    if fnmatch.fnmatchcase(normalized_path, normalized_pattern):
        return True
    if normalized_pattern.startswith("**/"):
        return fnmatch.fnmatchcase(normalized_path, normalized_pattern[3:])
    return False


def _is_dependency_path(path: str) -> bool:
    lowered = path.casefold().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    return (
        name in _DEPENDENCY_FILES
        or name in _LOCK_FILES
        or (name.startswith("requirements") and name.endswith((".txt", ".in")))
        or lowered.endswith("/gradle/libs.versions.toml")
        or name in {"build.gradle", "build.gradle.kts"}
        or name.endswith((".csproj", ".fsproj", ".gemspec", ".nuspec", ".vbproj"))
    )


def _is_workflow_path(path: str) -> bool:
    lowered = path.casefold().replace("\\", "/").removeprefix("./")
    name = lowered.rsplit("/", 1)[-1]
    return (
        lowered.startswith((".github/workflows/", ".github/actions/", ".circleci/", ".buildkite/"))
        or name in _WORKFLOW_FILES
    )


def _secret_findings(files: Sequence[_DiffFile]) -> list[str]:
    findings: set[str] = set()
    for item in files:
        for added_line in item.added_lines:
            for label, pattern in _SECRET_PATTERNS:
                if pattern.search(added_line):
                    findings.add(f"{label} in {item.path}")
            generic = _GENERIC_SECRET.search(added_line)
            if generic and not _OBVIOUS_PLACEHOLDER.search(generic.group(1)):
                findings.add(f"credential assignment in {item.path}")
    return sorted(findings)


def _path_evidence(kind: str, paths: Sequence[str]) -> str:
    if not paths:
        return f"no {kind}s detected"
    rendered = ", ".join(sorted(dict.fromkeys(paths))[:5])
    suffix = "" if len(set(paths)) <= 5 else f" (+{len(set(paths)) - 5} more)"
    return f"{kind}(s) detected: {rendered}{suffix}"


__all__ = ["QualityEvaluator", "evaluate_quality"]
