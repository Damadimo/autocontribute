from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from autocontribute.domain import FileEdit
from autocontribute.exceptions import RepositoryError
from autocontribute.repository import RepositoryWorkspace


def _git(repository: Path, *arguments: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture
def source_repository(tmp_path: Path) -> tuple[Path, str, str]:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    _git(source, "config", "user.name", "Fixture")
    _git(source, "config", "user.email", "fixture@example.invalid")

    (source / "README.md").write_text("first\n", encoding="utf-8")
    (source / "delete.txt").write_text("remove me\n", encoding="utf-8")
    (source / "CONTRIBUTING.md").write_text("Run tests.\n", encoding="utf-8")
    github = source / ".github"
    github.mkdir()
    (github / "PULL_REQUEST_TEMPLATE.md").write_text("Explain the change.\n", encoding="utf-8")
    (source / "SECURITY.md").write_text("Report privately.\n", encoding="utf-8")
    (source / "AI_POLICY.md").write_text("Disclose assistance.\n", encoding="utf-8")
    source_code = source / "src"
    source_code.mkdir()
    (source_code / "parser.py").write_text(
        "def parse_document(value: str) -> str:\n"
        "    return normalize_document(value)\n\n"
        "def normalize_document(value: str) -> str:\n"
        "    return value.strip()\n",
        encoding="utf-8",
    )
    (source / "binary.bin").write_bytes(b"\x00fixture")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "first")
    first_sha = _git(source, "rev-parse", "HEAD")

    (source / "README.md").write_text("second\n", encoding="utf-8")
    _git(source, "add", "README.md")
    _git(source, "commit", "--quiet", "-m", "second")
    second_sha = _git(source, "rev-parse", "HEAD")
    return source, first_sha, second_sha


def _clone(source: Path, sha: str, destination: Path) -> RepositoryWorkspace:
    return RepositoryWorkspace.clone(
        str(source), sha, destination, allow_local_source=True, timeout_seconds=30
    )


def _edit(
    operation: str,
    path: str,
    *,
    find: str | None = None,
    replace: str | None = None,
    content: str | None = None,
) -> FileEdit:
    return FileEdit(
        operation=operation,
        path=path,
        find=find,
        replace=replace,
        content=content,
        rationale="fixture",
    )


def test_clone_is_pinned_and_does_not_fetch_later_head(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, second_sha = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    assert workspace.base_sha == first_sha
    assert workspace.read_file("README.md") == "first\n"
    assert _git(workspace.path, "rev-parse", "HEAD") == first_sha
    assert first_sha != second_sha
    assert not (workspace.path / ".git" / "modules").exists()


def test_clone_fetch_disables_http_redirects_before_contacting_remote(
    tmp_path: Path,
    source_repository: tuple[Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, first_sha, _ = source_repository
    commands: list[list[str]] = []
    real_run = subprocess.run

    def recording_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        command = args[0] if args else kwargs["args"]
        if isinstance(command, list) and all(isinstance(item, str) for item in command):
            commands.append(command)
        return real_run(*args, **kwargs)  # type: ignore[call-overload,return-value]

    monkeypatch.setattr(subprocess, "run", recording_run)

    _clone(source, first_sha, tmp_path / "workspace")

    fetch = next(command for command in commands if "fetch" in command)
    redirect_option = fetch.index("http.followRedirects=false")
    assert fetch[redirect_option - 1] == "-c"
    assert redirect_option < fetch.index("fetch")


def test_clone_rejects_untrusted_sources_and_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "destination"
    destination.mkdir()
    with pytest.raises(RepositoryError, match="HTTPS"):
        RepositoryWorkspace.clone("ssh://example.test/repo", "a" * 40, tmp_path / "new")
    with pytest.raises(RepositoryError, match="already exists"):
        RepositoryWorkspace.clone(
            str(tmp_path),
            "a" * 40,
            destination,
            allow_local_source=True,
        )


def test_exact_edits_produce_reconstructable_patch_and_metrics(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    pristine = _clone(source, first_sha, tmp_path / "pristine")

    changed = workspace.apply_edits(
        [
            _edit("replace", "README.md", find="first\n", replace="improved\n"),
            _edit("create", "tests/new.txt", content="new coverage\n"),
            _edit("delete", "delete.txt"),
        ]
    )

    assert changed == ["README.md", "delete.txt", "tests/new.txt"]
    patch = workspace.diff()
    assert "diff --git a/README.md b/README.md" in patch
    assert "diff --git a/tests/new.txt b/tests/new.txt" in patch
    assert "deleted file mode" in patch
    assert "3 files changed" in workspace.diff_stat()
    metrics = workspace.metrics()
    assert metrics.changed_files == 3
    assert metrics.insertions == 2
    assert metrics.deletions == 2
    assert metrics.changed_lines == 4

    result = subprocess.run(
        ["git", "apply", "--binary", "-"],
        cwd=pristine.path,
        input=workspace.diff_bytes(),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    assert (pristine.path / "README.md").read_text(encoding="utf-8") == "improved\n"
    assert (pristine.path / "tests" / "new.txt").read_text(encoding="utf-8") == "new coverage\n"
    assert not (pristine.path / "delete.txt").exists()


def test_failed_edit_batch_rolls_back_prior_edits(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    with pytest.raises(RepositoryError, match="found 0"):
        workspace.apply_edits(
            [
                _edit("replace", "README.md", find="first", replace="changed"),
                _edit("replace", "CONTRIBUTING.md", find="missing", replace="nope"),
            ]
        )

    assert workspace.read_file("README.md") == "first\n"
    assert workspace.changed_paths() == []


def test_paths_cannot_escape_or_cross_symlinks(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (workspace.path / "link").symlink_to(tmp_path)

    with pytest.raises(RepositoryError, match="Unsafe repository path"):
        workspace.read_file("../outside.txt")
    with pytest.raises(RepositoryError, match="symlink"):
        workspace.read_file("link/outside.txt")
    with pytest.raises(RepositoryError, match="symlink"):
        workspace.apply_edit(_edit("replace", "link/outside.txt", find="secret", replace="x"))
    assert outside.read_text(encoding="utf-8") == "secret"


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "line\nbreak.py",
        "tab\tname.py",
        "delete\x7fname.py",
        "next\x85line.py",
        "bidi\u202ename.py",
    ],
)
def test_repository_paths_reject_control_and_format_characters(
    tmp_path: Path,
    source_repository: tuple[Path, str, str],
    unsafe_path: str,
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    with pytest.raises(RepositoryError, match="Unsafe repository path"):
        workspace.read_file(unsafe_path)
    with pytest.raises(RepositoryError, match="Unsafe repository path"):
        workspace.apply_edit(_edit("create", unsafe_path, content="unsafe\n"))


def test_tracked_control_character_path_fails_context_enumeration_closed(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    unsafe = workspace.path / "quoted\npath.py"
    unsafe.write_text("unsafe = True\n", encoding="utf-8")
    _git(workspace.path, "add", "--", unsafe.name)

    with pytest.raises(RepositoryError, match="Unsafe repository path"):
        workspace.context_index()


def test_exact_replace_rejects_ambiguous_matches(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    workspace.apply_edit(_edit("replace", "README.md", find="first", replace="first first"))

    with pytest.raises(RepositoryError, match="found 2"):
        workspace.apply_edit(_edit("replace", "README.md", find="first", replace="second"))


def test_context_index_and_guidance_are_bounded_and_include_policies(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    index = {entry.path: entry for entry in workspace.context_index()}
    assert index["README.md"].binary is False
    assert index["README.md"].lines == 1
    assert index["binary.bin"].binary is True

    guidance = workspace.guidance()
    assert "CONTRIBUTING.md" in guidance
    assert ".github/PULL_REQUEST_TEMPLATE.md" in guidance
    assert "SECURITY.md" in guidance
    assert "AI_POLICY.md" in guidance
    assert sum(map(len, guidance.values())) <= 120_000


def test_guidance_reserves_budget_for_complete_pull_request_templates(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    template = "Explain the change.\n"

    guidance = workspace.guidance(max_characters=len(template))

    assert guidance == {".github/PULL_REQUEST_TEMPLATE.md": template}
    with pytest.raises(RepositoryError, match="truncated template"):
        workspace.guidance(max_characters=len(template) - 1)


@pytest.mark.parametrize(
    ("edit", "path"),
    [
        (_edit("create", ".env.production", content="PASSWORD=value\n"), ".env.production"),
        (_edit("create", "config/private.pem", content="private\n"), "config/private.pem"),
    ],
)
def test_edits_to_sensitive_paths_are_rejected(
    tmp_path: Path,
    source_repository: tuple[Path, str, str],
    edit: FileEdit,
    path: str,
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    with pytest.raises(RepositoryError, match="sensitive repository path"):
        workspace.apply_edit(edit)

    assert not (workspace.path / path).exists()


def test_sensitive_file_deletion_is_rejected_before_batch_application(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    sensitive = workspace.path / ".env.production"
    sensitive.write_text("PASSWORD=live-value-123456\n", encoding="utf-8")

    with pytest.raises(RepositoryError, match="sensitive repository path"):
        workspace.apply_edits([_edit("delete", ".env.production")])

    assert sensitive.read_text(encoding="utf-8") == "PASSWORD=live-value-123456\n"


def test_literal_context_search_finds_symbols_without_executing_repository_code(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    matches = workspace.search_text(["parse_document", "normalize_document"])

    assert [(match.query, match.path, match.line_number) for match in matches] == [
        ("parse_document", "src/parser.py", 1),
        ("normalize_document", "src/parser.py", 2),
        ("normalize_document", "src/parser.py", 4),
    ]


def test_literal_context_search_is_bounded_and_rejects_unsafe_queries(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    matches = workspace.search_text(["document"], max_matches=10, max_line_characters=12)

    assert len(matches) >= 2
    assert all(len(match.line) <= 25 for match in matches)
    with pytest.raises(RepositoryError, match="results would be incomplete"):
        workspace.search_text(["document"], max_matches=2)
    with pytest.raises(RepositoryError, match="unsafe"):
        workspace.search_text(["bad\0query"])
    with pytest.raises(RepositoryError, match="at most 20"):
        workspace.search_text([f"query-{index}" for index in range(21)])


def test_literal_context_search_deduplicates_case_and_enforces_total_byte_budget(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    matches = workspace.search_text(["parse_document", "PARSE_DOCUMENT"])

    assert [(match.query, match.line_number) for match in matches] == [("parse_document", 1)]
    with pytest.raises(ValueError, match="limits must be positive"):
        workspace.search_text(["parse_document"], max_total_bytes=0)


def test_context_index_signals_byte_exhaustion_and_search_fails_closed(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    entries = workspace.context_index(max_total_bytes=1)

    assert any(not entry.content_inspected for entry in entries)
    with pytest.raises(RepositoryError, match="before inspecting every tracked file"):
        workspace.search_text(["parse_document"], max_total_bytes=1)


def test_context_index_fails_instead_of_omitting_files_at_file_limit(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")

    with pytest.raises(RepositoryError, match="file limit"):
        workspace.context_index(max_files=1)
