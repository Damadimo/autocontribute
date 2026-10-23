"""The first user message of each transcript, and the agent's nested guidance (DESIGN §6.3, §6.4).

System prompts stay byte-stable for a run, so every per-run fact goes in the first user message:
the issue, the project's guidance, the environment, and for the critic the change and the
controller's results. Text that the repository, the issue, its commenters or a model wrote is
untrusted, and goes into an :func:`autocontribute.untrusted.untrusted_block`.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from pydantic import JsonValue

from autocontribute.ai_policy import PolicyFile, RepositoryAiPolicy
from autocontribute.domain import IssueCandidate, RepositoryInfo
from autocontribute.environment_builder import FailedAttempt
from autocontribute.environment_signals import RepositorySignals
from autocontribute.environments import EnvironmentBaseline, EnvironmentRecipe
from autocontribute.exceptions import PolicyError
from autocontribute.fix_checks import FixCheckResult, SuiteRunEvidence
from autocontribute.pr_template import is_pull_request_template, select_pull_request_template
from autocontribute.repository import RepositoryWorkspace
from autocontribute.submissions import AgentSubmission, ReviewBlocker
from autocontribute.untrusted import untrusted_block

# Each guidance file, each policy file and the issue body is cut to this (DESIGN §6.4).
FILE_CHARACTERS: Final = 20_000
# What all guidance files may take together; later files are named, not quoted.
_GUIDANCE_CHARACTERS: Final = 50_000
_POLICY_CHARACTERS: Final = 80_000
_SIGNAL_CHARACTERS: Final = 100_000
_COMMENT_CHARACTERS: Final = 4_000
_COMMENTS_CHARACTERS: Final = 24_000
_MAX_READ_BYTES: Final = 1_000_000
_LISTED_TESTS: Final = 20
_CONTRIBUTING_DIRECTORIES: Final = frozenset({".", ".github", "docs"})
_AGENT_FILES: Final = ("AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md")
# Files whose content changes with every dependency update and says little about setup.
_LOCK_SUFFIXES: Final = (".lock", "-lock.json", "-lock.yaml", ".sum", ".lockb")
_SIGNAL_PRIORITY: Final = (
    "AGENTS.md",
    "CLAUDE.md",
    ".github/copilot-instructions.md",
    ".devcontainer/devcontainer.json",
    ".devcontainer.json",
)


@dataclass(frozen=True, slots=True)
class GuidanceFile:
    """One guidance file, cut to ``FILE_CHARACTERS`` when longer."""

    path: str
    text: str
    # The characters left out at the end; 0 when the file is whole.
    omitted: int


@dataclass(frozen=True, slots=True)
class Guidance:
    """The repository's guidance for the agent's first message."""

    contributing: tuple[GuidanceFile, ...]
    agent_instructions: tuple[GuidanceFile, ...]
    # One template, or every template when the repository has several and no default.
    pull_request_templates: tuple[GuidanceFile, ...]

    @property
    def paths(self) -> tuple[str, ...]:
        files = (*self.contributing, *self.agent_instructions, *self.pull_request_templates)
        return tuple(file.path for file in files)


@dataclass(frozen=True, slots=True)
class RunFacts:
    """What the controller knows about the run that every transcript of it may need."""

    issue: IssueCandidate
    repository: RepositoryInfo
    base_sha: str
    recipe: EnvironmentRecipe
    baseline: EnvironmentBaseline
    # The repository's AI-contribution policy as discovery read it; None when not read.
    ai_policy: RepositoryAiPolicy | None


def read_guidance(
    workspace: RepositoryWorkspace,
    *,
    organization_templates: Mapping[str, str] | None = None,
) -> Guidance:
    """Read the contributing guide, agent instruction files and pull request template.

    Files come from the workspace's tracked paths. A symlink is followed when it ends at a
    regular file inside the repository and outside ``.git``; anything else is skipped, as are
    files that are not UTF-8. ``organization_templates`` (path to text, from the owner's
    ``.github`` repository) apply when the repository has no template of its own.
    """

    paths = sorted(entry.path for entry in workspace.base_tree())
    root = workspace.path

    def read(candidates: Iterable[str]) -> tuple[GuidanceFile, ...]:
        found = (_read_file(root, path) for path in candidates)
        return tuple(file for file in found if file is not None)

    contributing = read(
        path
        for path in paths
        if str(PurePosixPath(path).parent) in _CONTRIBUTING_DIRECTORIES
        and PurePosixPath(path).name.upper().startswith("CONTRIBUTING")
    )
    folded = {path.casefold(): path for path in paths}
    agent_instructions = read(
        folded[name.casefold()] for name in _AGENT_FILES if name.casefold() in folded
    )
    templates = read(path for path in paths if is_pull_request_template(path))
    if not templates and organization_templates:
        templates = tuple(
            _cut_file(path, text)
            for path, text in sorted(organization_templates.items())
            if is_pull_request_template(path)
        )
    return Guidance(contributing, agent_instructions, _chosen_templates(templates))


def nested_agent_guidance(
    workspace: RepositoryWorkspace, *, host_values: frozenset[str]
) -> dict[str, str]:
    """Map each directory below the root that has an AGENTS.md to the message carrying it.

    The agent loop appends the message after the agent first edits under that directory.
    """

    messages: dict[str, str] = {}
    for entry in sorted(workspace.base_tree(), key=lambda entry: entry.path):
        pure = PurePosixPath(entry.path)
        if pure.name.casefold() != "agents.md" or str(pure.parent) == ".":
            continue
        file = _read_file(workspace.path, entry.path)
        if file is None:
            continue
        directory = str(pure.parent)
        messages[directory] = (
            f"{directory}/ has its own {pure.name}. It applies to the file you just edited and "
            f"to everything else under {directory}/:\n"
            + untrusted_block(file.path, _file_data(file), host_values=host_values)
        )
    return messages


def agent_task(
    facts: RunFacts,
    guidance: Guidance,
    *,
    commit_titles: Sequence[str],
    host_values: frozenset[str],
) -> str:
    """The agent's first message: the issue, the guidance, recent commits and the environment."""

    issue = facts.issue
    sections = [
        f"Fix issue #{issue.number} of {facts.repository.full_name}. The repository is at "
        f"/workspace, checked out at {facts.base_sha}.",
        _section("The issue", _issue_block(issue, host_values)),
        _section(
            "Recent commit titles",
            "The titles of the last commits up to the base commit, newest first; follow their "
            "style for the pull request title and the commit message.\n"
            + untrusted_block("recent commit titles", list(commit_titles), host_values=host_values)
            if commit_titles
            else "The repository's recent commit titles are not available.",
        ),
        _section("Project guidance", _guidance_text(guidance, host_values)),
    ]
    policy = _policy_text(facts.ai_policy, host_values)
    if policy is not None:
        sections.append(_section("The repository's AI policy", policy))
    sections.append(_section("Environment", _environment_text(facts, host_values)))
    return "\n\n".join(sections) + "\n"


def critic_task(
    facts: RunFacts,
    *,
    round_number: int,
    submission: AgentSubmission,
    patch: str,
    check: FixCheckResult,
    guidance_paths: Sequence[str],
    earlier_blockers: Sequence[ReviewBlocker],
    host_values: frozenset[str],
) -> str:
    """The critic's first message: the inputs DESIGN §7.2 lists, and earlier blockers."""

    issue = facts.issue
    facts_lines = [
        f"- Repository: {facts.repository.full_name}, default branch "
        f"{facts.repository.default_branch}, base commit {facts.base_sha}.",
        f"- Test command: `{facts.recipe.test_command}` ({facts.recipe.test_framework}).",
        f"- Before the change: {baseline_summary(facts.baseline)}",
    ]
    if guidance_paths:
        facts_lines.append(
            "- Contribution guidance, to read in /workspace: " + ", ".join(guidance_paths) + "."
        )
    sections = [
        f"Review the change prepared for issue #{issue.number} of "
        f"{facts.repository.full_name}. This is review round {round_number}.",
        _section("Repository facts", "\n".join(facts_lines)),
        _section("The issue", _issue_block(issue, host_values)),
    ]
    policy = _policy_text(facts.ai_policy, host_values)
    if policy is not None:
        sections.append(_section("The repository's AI policy", policy))
    sections += [
        _section(
            "The patch",
            "The author's change against the base commit; /workspace has it applied.\n"
            + untrusted_block("patch", patch, host_values=host_values),
        ),
        _section(
            "Pull request text",
            "The controller appends a testing note and an AI disclosure; do not ask for them.\n"
            + untrusted_block(
                "pull request text",
                {
                    "title": submission.pr_title,
                    "body": submission.pr_body,
                    "commit_message": submission.commit_message,
                },
                host_values=host_values,
            ),
        ),
        _section(
            "The author's summary",
            "These are the author's claims, not evidence.\n"
            + untrusted_block(
                "author's summary",
                {"summary": submission.summary, "test_files": list(submission.test_files)},
                host_values=host_values,
            ),
        ),
        _section("The controller's results", _check_text(check, host_values)),
    ]
    if check.test_waiver_needed:
        sections.append(
            _section(
                "No test",
                "The change edits source files but adds or changes no test. Set no_test_needed "
                "only when no test can show the fix, and say why in the summary; otherwise "
                "report a weak_test blocker.",
            )
        )
    if earlier_blockers:
        sections.append(
            _section(
                "Blockers from the previous round",
                "The author was asked to fix these. Check each one; report it again only if it "
                "still holds.\n"
                + untrusted_block(
                    "previous blockers",
                    [blocker.model_dump(mode="json") for blocker in earlier_blockers],
                    host_values=host_values,
                ),
            )
        )
    return "\n\n".join(sections) + "\n"


def setup_task(
    repository: str,
    signals: RepositorySignals,
    failed: FailedAttempt,
    *,
    allowed_hosts: Sequence[str],
    host_values: frozenset[str],
) -> str:
    """The setup agent's first message: the failed attempt and the repository's signals."""

    recipe = failed.recipe
    attempt: dict[str, JsonValue] = {
        "base_image": recipe.base_image,
        "system_packages": list(recipe.system_packages),
        "setup_commands": list(recipe.setup_commands),
        "build_commands": list(recipe.build_commands),
        "test_command": recipe.test_command,
        "why_it_failed": failed.reason,
        "log_tail": failed.log_tail,
    }
    sections = [
        f"Set up the test environment of {repository}. The container runs {recipe.base_image} "
        "with the repository at /workspace. The attempt below failed.",
        _section(
            "The failed attempt",
            untrusted_block("failed attempt", attempt, host_values=host_values),
        ),
        _section(
            "Network",
            "The proxy allows these hosts and refuses all others: "
            + ", ".join(sorted(allowed_hosts))
            + ".",
        ),
        _section("Build and test signals", _signals_text(signals, host_values)),
    ]
    return "\n\n".join(sections) + "\n"


def triage_task(
    issue: IssueCandidate, repository: RepositoryInfo, *, host_values: frozenset[str]
) -> str:
    """The triage model's message: the repository's facts and the issue with its comments."""

    facts = (
        f"Assess issue #{issue.number} of {repository.full_name} ({repository.stars} stars, "
        f"default branch {repository.default_branch})."
    )
    return f"{facts}\n\n{_section('The issue', _issue_block(issue, host_values))}\n"


def policy_task(
    repository: RepositoryInfo, files: Sequence[PolicyFile], *, host_values: frozenset[str]
) -> str:
    """The policy classifier's message: the repository's policy files that concern AI.

    Each file is named ``<repository>/<path>``, which may be the owner's ``.github``
    repository. Files are cut to ``FILE_CHARACTERS`` and stop at a total of 80,000
    characters; the rest are named.
    """

    blocks: list[str] = []
    omitted: list[str] = []
    remaining = _POLICY_CHARACTERS
    for file in files:
        name = f"{file.repository}/{file.path}"
        if remaining <= 0:
            omitted.append(name)
            continue
        cut = _cut_file(name, file.text, limit=min(FILE_CHARACTERS, remaining))
        remaining -= len(cut.text)
        blocks.append(untrusted_block(name, _file_data(cut), host_values=host_values))
    text = "\n".join(blocks) if blocks else "The repository has no policy file about AI."
    if omitted:
        text += "\nFiles left out for length: " + ", ".join(omitted)
    intro = f"Classify the AI contribution policy of {repository.full_name}. Its policy files:"
    return f"{intro}\n\n{text}\n"


def baseline_summary(baseline: EnvironmentBaseline) -> str:
    """One line on what the test command reported before any change."""

    if not baseline.per_test:
        verdict = "passed" if baseline.pass_stable else "failed"
        return f"the suite {verdict} in every run (it reports no per-test results)."
    duration = max(baseline.durations_seconds, default=0.0)
    return (
        f"{baseline.collected} tests: {len(baseline.pass_stable)} passed in every run, "
        f"{len(baseline.fail_before)} failed in every run, {len(baseline.flaky)} gave different "
        f"results, {len(baseline.skip)} skipped; the suite took about {duration:.0f} s."
    )


def _section(title: str, body: str) -> str:
    return f"## {title}\n\n{body}"


def _issue_block(issue: IssueCandidate, host_values: frozenset[str]) -> str:
    body, omitted = _cut(issue.body, FILE_CHARACTERS)
    comments: list[JsonValue] = []
    remaining = _COMMENTS_CHARACTERS
    for index, comment in enumerate(issue.discussion):
        if remaining <= 0:
            comments.append(f"{len(issue.discussion) - index} later comments left out")
            break
        text, cut = _cut(comment.body, min(_COMMENT_CHARACTERS, remaining))
        remaining -= len(text)
        comments.append(
            {
                "author": comment.author,
                "author_association": comment.author_association,
                "created_at": comment.created_at.isoformat(),
                "body": text + (f"\n[... {cut} more characters]" if cut else ""),
            }
        )
    data: dict[str, JsonValue] = {
        "number": issue.number,
        "url": issue.html_url,
        "title": issue.title,
        "author": issue.author,
        "labels": list(issue.labels),
        "body": body + (f"\n[... {omitted} more characters]" if omitted else ""),
        "comments": comments,
    }
    return untrusted_block(f"issue #{issue.number}", data, host_values=host_values)


def _guidance_text(guidance: Guidance, host_values: frozenset[str]) -> str:
    groups = (
        ("Contributing guide", guidance.contributing),
        ("Instructions for coding agents", guidance.agent_instructions),
        ("Pull request template", guidance.pull_request_templates),
    )
    if not any(files for _, files in groups):
        return (
            "The repository has no contributing guide, instructions for coding agents or pull "
            "request template."
        )
    parts: list[str] = []
    left_out: list[str] = []
    remaining = _GUIDANCE_CHARACTERS
    for title, files in groups:
        for file in files:
            if len(file.text) > remaining:
                left_out.append(file.path)
                continue
            remaining -= len(file.text)
            label = f"{title}: {file.path}"
            parts.append(untrusted_block(label, _file_data(file), host_values=host_values))
    if len(guidance.pull_request_templates) > 1:
        parts.append("The repository has several pull request templates; fill the one that fits.")
    if left_out:
        parts.append(
            "Also read these in /workspace; they are left out here for length: "
            + ", ".join(left_out)
        )
    return "\n".join(parts)


def _policy_text(policy: RepositoryAiPolicy | None, host_values: frozenset[str]) -> str | None:
    if policy is None or policy.stance == "none":
        return None
    data: dict[str, JsonValue] = {
        "stance": policy.stance,
        "requires_disclosure": policy.requires_disclosure,
        "disclosure_requirements": list(policy.disclosure_requirements),
        "requires_human_written_text": policy.requires_human_written_text,
        "quotes": [
            {"file": f"{quote.repository}/{quote.path}", "text": quote.text}
            for quote in policy.quotes
        ],
    }
    return (
        "What the repository's files say about AI-assisted contributions, quoted verbatim. "
        "The controller adds the disclosure and any required commit trailer.\n"
        + untrusted_block("AI policy", data, host_values=host_values)
    )


def _environment_text(facts: RunFacts, host_values: frozenset[str]) -> str:
    baseline = facts.baseline
    lines = [
        "- A Linux container with no network access; the dependencies are installed.",
        f"- Run the tests with: `{facts.recipe.test_command}`",
        f"- Before any change, that command reported: {baseline_summary(baseline)}",
    ]
    if baseline.fail_before:
        more = len(baseline.fail_before) - _LISTED_TESTS
        listed: list[JsonValue] = [*baseline.fail_before[:_LISTED_TESTS]]
        if more > 0:
            listed.append(f"and {more} more")
        lines.append(
            "- These tests already failed before any change; they are not yours to fix:\n"
            + untrusted_block("tests failing before any change", listed, host_values=host_values)
        )
    if baseline.timed_out:
        lines.append(
            "- The full suite does not finish within the time limit; run the tests near your "
            "change."
        )
    return "\n".join(lines)


def _check_text(check: FixCheckResult, host_values: frozenset[str]) -> str:
    """Return the statuses as controller text and the details as untrusted data.

    The details name the repository's tests and files.
    """

    failed = [gate.gate for gate in check.gates if not gate.passed]
    lines = ["Gates: " + (f"failed: {', '.join(failed)}." if failed else "all passed.")]
    data: dict[str, JsonValue] = {
        "gates": [gate.model_dump(mode="json") for gate in check.gates],
        "red_green": None,
        "regression": None,
    }
    red_green = check.red_green
    if red_green is not None:
        lines.append(f"Red/green: {red_green.status}.")
        data["red_green"] = {
            "detail": red_green.detail,
            "targets": list(red_green.targets),
            "reproduced": list(red_green.reproduced),
            "uncollected": list(red_green.uncollected),
            "runs": [_run_data(run) for run in red_green.runs],
        }
    regression = check.regression
    if regression is not None:
        lines.append(f"Patched suite against the baseline: {regression.status}.")
        data["regression"] = {
            "detail": regression.detail,
            "full_suite": regression.full_suite,
            "new_failures": list(regression.new_failures),
            "runs": [_run_data(run) for run in regression.runs],
        }
    lines.append(untrusted_block("controller results", data, host_values=host_values))
    return "\n".join(lines)


def _run_data(run: SuiteRunEvidence) -> dict[str, JsonValue]:
    return run.model_dump(mode="json", exclude={"output_tail"})


def _signals_text(signals: RepositorySignals, host_values: frozenset[str]) -> str:
    def priority(path: str) -> tuple[int, str]:
        rank = _SIGNAL_PRIORITY.index(path) if path in _SIGNAL_PRIORITY else len(_SIGNAL_PRIORITY)
        workflow = 0 if path.startswith(".github/workflows/") else 1
        return rank, f"{workflow}{path}"

    blocks: list[str] = []
    left_out: list[str] = []
    remaining = _SIGNAL_CHARACTERS
    for path in sorted(signals.files, key=priority):
        if path.endswith(_LOCK_SUFFIXES) or remaining <= 0:
            left_out.append(path)
            continue
        file = _cut_file(path, signals.files[path], limit=min(FILE_CHARACTERS, remaining))
        remaining -= len(file.text)
        blocks.append(untrusted_block(path, _file_data(file), host_values=host_values))
    text = "\n".join(blocks) or "The controller found no build or test signal files."
    if left_out:
        text += "\nRead these in /workspace if you need them: " + ", ".join(left_out)
    return text


def _read_file(root: Path, relative: str) -> GuidanceFile | None:
    """Read a UTF-8 file of at most 1 MB, following symlinks only to regular files inside the
    repository."""

    try:
        resolved = (root / relative).resolve(strict=True)
        inside = resolved.relative_to(root.resolve())
    except (OSError, ValueError, RuntimeError):
        return None
    if ".git" in inside.parts or not resolved.is_file():
        return None
    try:
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read(_MAX_READ_BYTES + 1)
        if len(data) > _MAX_READ_BYTES:
            return None
        text = data.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return _cut_file(relative, text)


def _cut_file(path: str, text: str, *, limit: int = FILE_CHARACTERS) -> GuidanceFile:
    kept, omitted = _cut(text, limit)
    return GuidanceFile(path, kept, omitted)


def _cut(text: str, limit: int) -> tuple[str, int]:
    if len(text) <= limit:
        return text, 0
    return text[:limit], len(text) - limit


def _file_data(file: GuidanceFile) -> dict[str, JsonValue]:
    data: dict[str, JsonValue] = {"path": file.path, "text": file.text}
    if file.omitted:
        data["note"] = (
            f"Cut after {len(file.text):,} characters; {file.omitted:,} more are in the file."
        )
    return data


def _chosen_templates(templates: tuple[GuidanceFile, ...]) -> tuple[GuidanceFile, ...]:
    try:
        selected = select_pull_request_template({file.path: file.text for file in templates})
    except PolicyError:
        return templates
    if selected is None:
        return ()
    return tuple(file for file in templates if file.path == selected[0])


__all__ = [
    "FILE_CHARACTERS",
    "Guidance",
    "GuidanceFile",
    "RunFacts",
    "agent_task",
    "baseline_summary",
    "critic_task",
    "nested_agent_guidance",
    "policy_task",
    "read_guidance",
    "setup_task",
    "triage_task",
]
