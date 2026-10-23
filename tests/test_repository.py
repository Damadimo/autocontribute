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
        "REQUESTS_CA_BUNDLE": "/operator/requests-ca.pem",
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


def test_exact_edits_produce_reconstructable_patch(
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


def _plant_program(tmp_path: Path, name: str) -> tuple[Path, Path]:
    """Write a host program that leaves a marker file when anything runs it."""

    marker = tmp_path / f"{name}-ran"
    program = tmp_path / f"{name}.sh"
    program.write_text(f'#!/bin/sh\ntouch "{marker}"\ncat\n', encoding="utf-8")
    program.chmod(0o755)
    return program, marker


@pytest.mark.parametrize("variable", ["clean", "smudge", "process"])
def test_planted_filter_driver_is_refused_before_host_git_runs_it(
    tmp_path: Path, source_repository: tuple[Path, str, str], variable: str
) -> None:
    # The map-sandbox §0.10 attack: a writable .git/config plus a .gitattributes line
    # made `git add --all` in the temporary index run a chosen command on the host.
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    pristine = _clone(source, first_sha, tmp_path / "pristine")
    program, marker = _plant_program(tmp_path, "filter")
    for target in (workspace, pristine):
        with (target.path / ".git" / "config").open("a", encoding="utf-8") as config:
            config.write(f'[filter "Planted.x"]\n\t{variable} = {program}\n')
        (target.path / ".gitattributes").write_text("* filter=Planted.x\n", encoding="utf-8")
    (workspace.path / "README.md").write_text("changed\n", encoding="utf-8")

    for operation in (
        workspace.changed_paths,
        workspace.diff_bytes,
        workspace.patch_bytes,
        lambda: pristine.apply_patch("diff --git a/x b/x\n"),
    ):
        with pytest.raises(RepositoryError, match=r"filter command: filter\.Planted\.x\."):
            operation()
    assert not marker.exists()


@pytest.mark.parametrize(
    ("config", "attributes"),
    [
        ("[core]\n\tfsmonitor = {program}\n", None),
        ("[diff]\n\texternal = {program}\n", None),
        ('[diff "planted"]\n\ttextconv = {program}\n\tcommand = {program}\n', "* diff=planted\n"),
    ],
)
def test_planted_git_programs_do_not_run_during_patch_extraction(
    tmp_path: Path,
    source_repository: tuple[Path, str, str],
    config: str,
    attributes: str | None,
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    program, marker = _plant_program(tmp_path, "program")
    with (workspace.path / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write(config.format(program=program))
    if attributes is not None:
        (workspace.path / ".gitattributes").write_text(attributes, encoding="utf-8")
    (workspace.path / "README.md").write_text("changed\n", encoding="utf-8")

    patch = workspace.patch_bytes()

    assert b"+changed" in patch
    assert workspace.changed_paths()
    assert not marker.exists()


def test_patch_bytes_keeps_symlinks_for_the_diff_gates(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    (workspace.path / "link").symlink_to("/etc/passwd")

    patch = workspace.patch_bytes()

    assert b"new file mode 120000" in patch
    with pytest.raises(RepositoryError, match="symlink"):
        workspace.diff_bytes()


def test_apply_patch_checks_the_whole_patch_before_changing_anything(
    tmp_path: Path, source_repository: tuple[Path, str, str]
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    target = _clone(source, first_sha, tmp_path / "target")
    (workspace.path / "README.md").write_text("improved\n", encoding="utf-8")
    (workspace.path / "delete.txt").unlink()
    patch = workspace.patch_bytes().decode("utf-8")

    (target.path / "delete.txt").write_text("drifted\n", encoding="utf-8")
    with pytest.raises(RepositoryError, match="patch does not apply"):
        target.apply_patch(patch)
    assert (target.path / "README.md").read_text(encoding="utf-8") == "first\n"

    (target.path / "delete.txt").write_text("remove me\n", encoding="utf-8")
    target.apply_patch(patch)
    assert (target.path / "README.md").read_text(encoding="utf-8") == "improved\n"
    assert not (target.path / "delete.txt").exists()
    with pytest.raises(RepositoryError, match="empty patch"):
        target.apply_patch("")


def test_temporary_index_keeps_the_index_mtime_so_racy_edits_are_seen(
    tmp_path: Path, source_repository: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Git rehashes an entry whose mtime is not older than the index file's. A copy with a
    # fresh mtime made it trust stat data instead, and a same-size edit made in the second
    # of the checkout vanished from the patch.
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    index_mtime = (workspace.path / ".git" / "index").stat().st_mtime_ns
    seen: list[int] = []
    real_run = subprocess.run

    def recording_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        environment = kwargs.get("env")
        if isinstance(environment, dict) and "GIT_INDEX_FILE" in environment:
            seen.append(os.stat(environment["GIT_INDEX_FILE"]).st_mtime_ns)
        return real_run(*args, **kwargs)  # type: ignore[call-overload,no-any-return]

    monkeypatch.setattr(subprocess, "run", recording_run)
    workspace.patch_bytes()

    assert seen and seen[0] == index_mtime


def test_fetching_tags_gives_version_tools_the_history_they_describe(
    source_repository: tuple[Path, str, str], tmp_path: Path
) -> None:
    source, first_sha, second_sha = source_repository
    _git(source, "tag", "v1.2.0", first_sha)
    workspace = _clone(source, second_sha, tmp_path / "workspace")
    assert _git(workspace.path, "tag") == ""

    with pytest.raises(RepositoryError, match="Git operation failed"):
        workspace.fetch_tags()
    workspace.fetch_tags(allow_local_source=True)

    assert _git(workspace.path, "describe", "--tags") == "v1.2.0-1-g" + second_sha[:7]
    assert _git(workspace.path, "rev-parse", "--is-shallow-repository") == "false"
    assert _git(workspace.path, "rev-parse", "HEAD") == second_sha


def test_fetching_submodules_checks_out_the_recorded_commit(
    source_repository: tuple[Path, str, str], tmp_path: Path
) -> None:
    source, _, _ = source_repository
    library = tmp_path / "library"
    library.mkdir()
    _git(library, "init", "--quiet")
    (library / "lib.txt").write_text("vendored\n", encoding="utf-8")
    _git(library, "add", "lib.txt")
    _git(library, "-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "l")
    _git(source, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "lib")
    _git(source, "commit", "--quiet", "-m", "add submodule")
    workspace = _clone(source, _git(source, "rev-parse", "HEAD"), tmp_path / "workspace")

    with pytest.raises(RepositoryError):
        workspace.fetch_submodules()
    workspace.fetch_submodules(allow_local_source=True)

    assert (workspace.path / "lib" / "lib.txt").read_text(encoding="utf-8") == "vendored\n"
    assert workspace.changed_paths() == []


def test_restoring_the_base_undoes_tracked_and_new_files_but_keeps_ignored_ones(
    source_repository: tuple[Path, str, str], tmp_path: Path
) -> None:
    source, _, second_sha = source_repository
    workspace = _clone(source, second_sha, tmp_path / "workspace")
    (workspace.path / ".git" / "info" / "exclude").write_text("build/\n*.log\n", encoding="utf-8")
    (workspace.path / "README.md").write_text("rewritten by setup\n", encoding="utf-8")
    (workspace.path / "delete.txt").unlink()
    (workspace.path / "src" / "_version.py").write_text("version = '0.1'\n", encoding="utf-8")
    (workspace.path / "*.md").write_text("glob-named\n", encoding="utf-8")
    (workspace.path / "linked").symlink_to(workspace.path / "README.md")
    (workspace.path / "build").mkdir()
    (workspace.path / "build" / "out.o").write_bytes(b"\x7fELF")
    (workspace.path / "setup.log").write_text("log\n", encoding="utf-8")

    restored = workspace.restore_base()

    assert restored == ["*.md", "README.md", "delete.txt", "linked", "src/_version.py"]
    assert workspace.changed_paths() == []
    assert (workspace.path / "README.md").read_text(encoding="utf-8") == "second\n"
    assert (workspace.path / "delete.txt").read_text(encoding="utf-8") == "remove me\n"
    assert (workspace.path / "CONTRIBUTING.md").read_text(encoding="utf-8") == "Run tests.\n"
    assert not os.path.lexists(workspace.path / "linked")
    assert (workspace.path / "build" / "out.o").is_file()
    assert workspace.ignored_paths() == ["build/", "setup.log"]

    workspace.remove_ignored()

    assert workspace.ignored_paths() == []
    assert (workspace.path / "README.md").is_file()


def _workspace_with_submodule(
    source_repository: tuple[Path, str, str], tmp_path: Path
) -> RepositoryWorkspace:
    source, _, _ = source_repository
    library = tmp_path / "library"
    library.mkdir()
    _git(library, "init", "--quiet")
    (library / "lib.txt").write_text("vendored\n", encoding="utf-8")
    _git(library, "add", "lib.txt")
    _git(library, "-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "l")
    _git(
        source, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "vendor"
    )
    _git(source, "commit", "--quiet", "-m", "add submodule")
    return _clone(source, _git(source, "rev-parse", "HEAD"), tmp_path / "workspace")


def test_host_git_never_enters_a_repository_planted_at_a_submodule_path(
    source_repository: tuple[Path, str, str], tmp_path: Path
) -> None:
    # `git add --all` ran `git status` inside a submodule whose checkout matched the recorded
    # commit, and that child git ran the clean filter a container planted in its config.
    workspace = _workspace_with_submodule(source_repository, tmp_path)
    program, marker = _plant_program(tmp_path, "nested")
    nested = workspace.path / "vendor"
    _git(nested, "init", "--quiet")
    (nested / "file.txt").write_text("one\n", encoding="utf-8")
    _git(nested, "add", "file.txt")
    _git(nested, "-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "n")
    with (nested / ".git" / "config").open("a", encoding="utf-8") as config:
        config.write(f'[filter "planted"]\n\tclean = {program}\n')
    (nested / ".gitattributes").write_text("* filter=planted\n", encoding="utf-8")
    (nested / "file.txt").write_text("two\n", encoding="utf-8")
    recorded = _git(workspace.path, "ls-tree", "HEAD", "vendor").split()[2]
    branch = _git(nested, "symbolic-ref", "HEAD")
    (nested / ".git" / branch).write_text(f"{recorded}\n", encoding="utf-8")
    (workspace.path / "README.md").write_text("changed\n", encoding="utf-8")

    patch = workspace.patch_bytes()
    changed = workspace.changed_paths()
    restored = workspace.restore_base()

    assert not marker.exists()
    assert b"+changed" in patch and b"vendor" not in patch
    assert changed == ["README.md"]
    assert restored == ["README.md"]


def test_restoring_the_base_deletes_a_new_nested_repository(
    source_repository: tuple[Path, str, str], tmp_path: Path
) -> None:
    source, first_sha, _ = source_repository
    workspace = _clone(source, first_sha, tmp_path / "workspace")
    nested = workspace.path / "cache" / "checkout"
    nested.mkdir(parents=True)
    _git(nested, "init", "--quiet")
    (nested / "file.txt").write_text("fetched\n", encoding="utf-8")
    _git(nested, "add", "file.txt")
    _git(nested, "-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "n")
    (nested / "outside").symlink_to(tmp_path)

    assert workspace.restore_base() == ["cache/checkout"]

    assert not (workspace.path / "cache" / "checkout").exists()
    assert (tmp_path / "workspace" / "README.md").is_file()
    assert workspace.changed_paths() == []
