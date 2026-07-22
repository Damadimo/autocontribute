from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import autocontribute.repository as repository_module
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


def test_git_environment_inherits_only_transport_and_runtime_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inherited = {
        "ALL_PROXY": "socks5://proxy.example.test:1080",
        "COMSPEC": "C:/Windows/System32/cmd.exe",
        "GIT_SSL_CAINFO": "/operator/ca.pem",
        "GIT_SSL_CAPATH": "/operator/certs",
        "HTTPS_PROXY": "https://proxy.example.test:8443",
        "HTTP_PROXY": "http://proxy.example.test:8080",
        "NO_PROXY": "localhost,127.0.0.1",
        "PATH": "/operator/bin:/usr/bin:/bin",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "SSL_CERT_DIR": "/system/certs",
        "SSL_CERT_FILE": "/system/ca.pem",
        "SYSTEMROOT": "C:/Windows",
        "TEMP": "C:/Temp",
        "TMP": "/operator/tmp-fallback",
        "TMPDIR": "/operator/tmp",
        "WINDIR": "C:/Windows",
        "all_proxy": "socks5://lower-proxy.example.test:1080",
        "http_proxy": "http://lower-proxy.example.test:8080",
        "https_proxy": "https://lower-proxy.example.test:8443",
        "no_proxy": "metadata.example.test",
    }
    denied = {
        # Provider, GitHub, cloud, and application credentials.
        "ANTHROPIC_API_KEY": "provider-secret",
        "AUTOCONTRIBUTE_GITHUB_TOKEN": "github-secret",
        "AWS_SECRET_ACCESS_KEY": "cloud-secret",
        "DATABASE_URL": "postgres://credential@example.test/database",
        "GH_TOKEN": "gh-secret",
        "GITHUB_TOKEN": "actions-secret",
        "OPENAI_API_KEY": "model-secret",
        # Git execution and repository redirection controls.
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/attacker/objects",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": "/attacker/hooks",
        "GIT_DIR": "/attacker/git-dir",
        "GIT_EXEC_PATH": "/attacker/git-exec",
        "GIT_PROXY_COMMAND": "/attacker/proxy",
        "GIT_SSH_COMMAND": "/attacker/ssh",
        "GIT_WORK_TREE": "/attacker/work-tree",
        "SSH_ASKPASS": "/attacker/askpass",
        "SSH_AUTH_SOCK": "/attacker/agent.sock",
        # Native dynamic-loader injection.
        "DYLD_FRAMEWORK_PATH": "/attacker/frameworks",
        "DYLD_INSERT_LIBRARIES": "/attacker/inject.dylib",
        "DYLD_LIBRARY_PATH": "/attacker/libraries",
        "LD_LIBRARY_PATH": "/attacker/libraries",
        "LD_PRELOAD": "/attacker/inject.so",
        "LIBPATH": "/attacker/libraries",
        "SHLIB_PATH": "/attacker/libraries",
        # Python process and import injection.
        "PYTHONHOME": "/attacker/python",
        "PYTHONINSPECT": "1",
        "PYTHONPATH": "/attacker/modules",
        "PYTHONSTARTUP": "/attacker/startup.py",
        "PYTHONWARNINGS": "error",
        "REQUESTS_CA_BUNDLE": "/attacker/requests-ca.pem",
        "VIRTUAL_ENV": "/attacker/venv",
    }
    monkeypatch.setattr(repository_module.os, "environ", {**inherited, **denied})

    environment = repository_module._git_environment()

    fixed = {
        "GIT_ASKPASS": "",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_EXTERNAL_DIFF": "",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
    }
    assert environment == {**inherited, **fixed}
    assert set(environment).isdisjoint(denied)


def test_local_clone_and_temporary_index_scrub_parent_process_environment(
    tmp_path: Path,
    source_repository: tuple[Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, first_sha, _ = source_repository
    temporary_root = tmp_path / "git-temporary"
    temporary_root.mkdir()
    denied_names = (
        "AUTOCONTRIBUTE_GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONHOME",
        "PYTHONPATH",
    )
    for name in denied_names:
        monkeypatch.setenv(name, f"sensitive-{name.casefold()}")
    monkeypatch.setenv("TMPDIR", str(temporary_root))
    monkeypatch.setattr(repository_module.tempfile, "tempdir", str(temporary_root))

    calls: list[tuple[list[str], dict[str, str]]] = []
    real_run = subprocess.run

    def recording_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        command = args[0] if args else kwargs["args"]
        environment = kwargs.get("env")
        if (
            isinstance(command, list)
            and command
            and command[0] == "git"
            and isinstance(environment, dict)
            and all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in environment.items()
            )
        ):
            calls.append((command, environment.copy()))
        return real_run(*args, **kwargs)  # type: ignore[call-overload,return-value]

    monkeypatch.setattr(subprocess, "run", recording_run)

    workspace = _clone(source, first_sha, tmp_path / "workspace")
    (workspace.path / "README.md").write_text("changed\n", encoding="utf-8")
    workspace.diff_bytes()

    assert any("fetch" in command for command, _environment in calls)
    temporary_index_environments = [
        environment for _command, environment in calls if "GIT_INDEX_FILE" in environment
    ]
    assert temporary_index_environments
    assert all(
        Path(environment["GIT_INDEX_FILE"]).is_relative_to(temporary_root)
        for environment in temporary_index_environments
    )
    for _command, environment in calls:
        assert environment["TMPDIR"] == str(temporary_root)
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
        assert environment["GIT_ASKPASS"] == ""
        assert set(environment).isdisjoint(denied_names)


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


def test_guidance_never_drops_or_truncates_applicable_files_to_fit_limits(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    complete = workspace.guidance()
    exact_characters = sum(len(content) for content in complete.values())

    assert workspace.guidance(max_characters=exact_characters) == complete
    with pytest.raises(RepositoryError, match=r"refusing to (?:omit|truncate)"):
        workspace.guidance(max_characters=exact_characters - 1)
    with pytest.raises(RepositoryError, match="refusing an incomplete guidance set"):
        workspace.guidance(max_files=len(complete) - 1)


def test_guidance_read_failure_is_not_silently_skipped(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    security = workspace.path / "SECURITY.md"
    security.unlink()
    security.symlink_to("README.md")

    with pytest.raises(
        RepositoryError,
        match=r"Could not load applicable repository guidance in full: SECURITY[.]md",
    ):
        workspace.guidance()


def test_guidance_uses_path_scoped_agents_and_readmes_without_loading_unrelated_readmes(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, _, _ = source_repository
    (source / "AGENTS.md").write_text("Repository rules.\n", encoding="utf-8")
    package = source / "src" / "package"
    package.mkdir(parents=True)
    (source / "src" / "AGENTS.md").write_text("Source rules.\n", encoding="utf-8")
    (source / "src" / "README.md").write_text("Source conventions.\n", encoding="utf-8")
    (package / "AGENTS.md").write_text("Package rules.\n", encoding="utf-8")
    (package / "README.md").write_text("Package conventions.\n", encoding="utf-8")
    (package / "module.py").write_text("value = 1\n", encoding="utf-8")
    unrelated = source / "unrelated"
    unrelated.mkdir()
    (unrelated / "AGENTS.md").write_text("Unrelated rules.\n", encoding="utf-8")
    (unrelated / "README.md").write_text("u" * 120_001, encoding="utf-8")
    nested_policy = unrelated / "CONTRIBUTION_POLICY.md"
    nested_policy.write_text("Repository-wide contribution policy.\n", encoding="utf-8")
    alternate_policy = unrelated / "PROJECT-SECURITY-POLICY.adoc"
    alternate_policy.write_text("Repository-wide security policy.\n", encoding="utf-8")
    extensionless_policy = unrelated / "AI_POLICY"
    extensionless_policy.write_text("Repository-wide AI policy.\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "add scoped guidance")
    sha = _git(source, "rev-parse", "HEAD")
    workspace = _clone(source, sha, tmp_path / "workspace")

    global_guidance = workspace.guidance()
    assert "AGENTS.md" in global_guidance
    assert "README.md" in global_guidance
    assert "unrelated/CONTRIBUTION_POLICY.md" in global_guidance
    assert "unrelated/PROJECT-SECURITY-POLICY.adoc" in global_guidance
    assert "unrelated/AI_POLICY" in global_guidance
    assert "src/AGENTS.md" not in global_guidance
    assert "src/README.md" not in global_guidance
    assert "unrelated/AGENTS.md" not in global_guidance
    assert "unrelated/README.md" not in global_guidance

    scoped = workspace.guidance(target_paths=["src/package/module.py"])
    assert "src/AGENTS.md" in scoped
    assert "src/README.md" in scoped
    assert "src/package/AGENTS.md" in scoped
    assert "src/package/README.md" in scoped
    assert "unrelated/AGENTS.md" not in scoped
    assert "unrelated/README.md" not in scoped
    scoped_paths = list(scoped)
    assert scoped_paths.index("AGENTS.md") < scoped_paths.index("src/AGENTS.md")
    assert scoped_paths.index("src/AGENTS.md") < scoped_paths.index("src/package/AGENTS.md")


def test_non_utf8_policy_fails_guidance_closed(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, _, _ = source_repository
    (source / "POLICY.md").write_bytes(b"invalid: \xff\n")
    _git(source, "add", "POLICY.md")
    _git(source, "commit", "--quiet", "-m", "add invalid policy")
    sha = _git(source, "rev-parse", "HEAD")
    workspace = _clone(source, sha, tmp_path / "workspace")

    with pytest.raises(
        RepositoryError,
        match=r"Could not load applicable repository guidance in full: POLICY[.]md",
    ):
        workspace.guidance()


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
