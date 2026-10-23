"""Opt-in test of the fix checks and one critic round against a real Docker daemon.

A scripted provider plays the agent and the critic. Everything else is real: the agent's
session, the checks' red/green and regression runs in fresh network-less containers on
workspace copies, the critic's session on a throwaway copy of ``V`` and its blocker checks.
The fixture repository's test runner writes a JUnit report with the standard library, so the
pinned Python image needs no setup. Enabled by the security-integration workflow.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import JsonValue
from test_agent_loop import Raw, ScriptedProvider, Shell, Submit, turn
from test_task_messages import _issue, _repository

from autocontribute.agent_loop import Solver, SubmittedFix
from autocontribute.agent_tools import SessionTools
from autocontribute.budget import RunBudget
from autocontribute.config import PolicyConfig, QualityConfig, SandboxConfig
from autocontribute.critic import Critic, CriticRound
from autocontribute.environment_builder import PreparedEnvironment
from autocontribute.environment_setup import EnvironmentImage
from autocontribute.environments import EnvironmentRecipe
from autocontribute.fix_checks import FixChecks
from autocontribute.instructions import load_instructions
from autocontribute.patches import extract_patch
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import SessionContainer, docker_client_environment
from autocontribute.store import RunStore
from autocontribute.suite_runs import run_baseline
from autocontribute.task_messages import RunFacts
from autocontribute.transcript import start_transcript
from autocontribute.validation_sandbox import DockerValidation
from autocontribute.workspace_copies import copy_workspace
from autocontribute.workspace_files import WorkspaceFiles

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTOCONTRIBUTE_RUN_DOCKER_TESTS") != "1",
    reason="set AUTOCONTRIBUTE_RUN_DOCKER_TESTS=1 to run live Docker validation tests",
)

# The smallest official Python image, as in test_agent_loop_live.py.
_PYTHON = "python@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530"
_CONFIG = SandboxConfig(memory="512m", cpus=1.0, pids_limit=64, command_timeout_seconds=120)
_REPORT = "/tmp/ac-report.xml"
# Runs every unittest module at the root and writes a JUnit report as pytest names its tests.
_RUNNER = """import glob, importlib, sys, unittest
from xml.sax.saxutils import escape, quoteattr

def tests(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from tests(test)
        else:
            yield test

cases, failed = [], False
for path in sorted(glob.glob("test_*.py")):
    module = path[:-3]
    try:
        loaded = importlib.import_module(module)
    except Exception as error:
        message = f"{type(error).__name__}: {error}"
        cases.append(("", module, "error", message))
        failed = True
        continue
    for test in tests(unittest.defaultTestLoader.loadTestsFromModule(loaded)):
        result = unittest.TestResult()
        test.run(result)
        problems = [("failure", text) for _, text in result.failures]
        problems += [("error", text) for _, text in result.errors]
        outcome, text = problems[0] if problems else ("", "")
        failed = failed or bool(problems)
        message = text.strip().splitlines()[-1] if text else ""
        cases.append((f"{module}.{type(test).__name__}", test._testMethodName, outcome, message))
with open(sys.argv[1], "w") as report:
    report.write("<testsuites><testsuite>")
    for classname, name, outcome, message in cases:
        inner = ""
        if outcome:
            inner = f"<{outcome} message={quoteattr(message)}>{escape(message)}</{outcome}>"
        attributes = f"classname={quoteattr(classname)} name={quoteattr(name)}"
        report.write(f"<testcase {attributes}>{inner}</testcase>")
    report.write("</testsuite></testsuites>")
print("\\n".join(f"{c} {n} {o or 'ok'}" for c, n, o, _ in cases))
sys.exit(1 if failed else 0)
"""
_TESTS = (
    "import unittest\n\nfrom calc import add\n\n\n"
    "class AddTest(unittest.TestCase):\n"
    "    def test_zero(self):\n"
    "        self.assertEqual(add(0, 0), 0)\n"
)
_FIX: dict[str, JsonValue] = {
    "outcome": "fixed",
    "skip_reason": None,
    "summary": "add subtracted its arguments; it now adds them.",
    "pr_title": "Fix add returning the difference",
    "pr_body": "add returned a - b. It now returns a + b.\n\nFixes #7",
    "commit_message": "Fix add returning the difference",
    "test_files": ["test_calc.py"],
    "test_command": f"python run_tests.py {_REPORT}",
}


def _docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=docker_client_environment(),
    )


@pytest.fixture(scope="module")
def python_image() -> Iterator[str]:
    if shutil.which("docker") is None:
        pytest.fail("live Docker tests were requested but Docker is not installed")
    present = _docker("image", "inspect", _PYTHON).returncode == 0
    if not present:
        pulled = _docker("pull", "--quiet", _PYTHON)
        assert pulled.returncode == 0, pulled.stderr
    try:
        yield _PYTHON
    finally:
        if not present:
            _docker("image", "rm", _PYTHON)


@pytest.fixture
def live_root() -> Iterator[Path]:
    # Colima shares only $HOME with its VM, and pytest's tmp_path is outside it on macOS.
    with tempfile.TemporaryDirectory(
        prefix=".autocontribute-live-", dir=Path(__file__).resolve().parents[1]
    ) as temporary:
        yield Path(temporary)


def _fixture_repository(root: Path) -> RepositoryWorkspace:
    source = root / "source"
    source.mkdir()
    files = {
        ".gitignore": "__pycache__/\n",
        "calc.py": "def add(a, b):\n    return a - b\n",
        "test_calc.py": _TESTS,
        "run_tests.py": _RUNNER,
    }
    for relative, content in files.items():
        (source / relative).write_text(content, encoding="utf-8")
    environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    for arguments in (
        ["init", "--quiet"],
        ["add", "."],
        ["-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "base"],
    ):
        subprocess.run(["git", *arguments], cwd=source, env=environment, check=True)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (root / "run").mkdir()
    return RepositoryWorkspace.clone(
        str(source), base, root / "run" / "repository", allow_local_source=True
    )


def _recipe() -> EnvironmentRecipe:
    return EnvironmentRecipe(
        repository="acme/calc",
        language="python",
        base_image=_PYTHON,
        system_packages=[],
        setup_commands=[],
        build_commands=[],
        test_command=f"python run_tests.py {_REPORT}",
        test_framework="pytest",
        test_report=_REPORT,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        offline_env={},
        fetch_tags=False,
        fetch_submodules=False,
        source="config",
        dependency_digest="b" * 64,
    )


def _texts(items: list[dict[str, JsonValue]]) -> str:
    return json.dumps(items)


def test_live_fix_checks_and_a_critic_round(live_root: Path, python_image: str) -> None:
    workspace = _fixture_repository(live_root)
    store = RunStore(live_root / "state")
    manifest = store.create_run()
    run_id = manifest.run_id
    budget = RunBudget(
        store,
        manifest,
        max_cost_usd=Decimal(10),
        max_model_calls=200,
        max_run_minutes=20,
        assert_lease=lambda: None,
    )
    recipe = _recipe()
    snapshot = workspace.path.with_name("repository.snapshot")
    copy_workspace(workspace.path, snapshot)
    baseline, _ = run_baseline(
        _CONFIG,
        image_id=python_image,
        recipe=recipe,
        snapshot=snapshot,
        base_sha=workspace.base_sha,
        run_id=run_id,
        store_root=store.root,
    )
    assert baseline.pass_stable == ["test_calc.AddTest::test_zero"]
    image = EnvironmentImage(python_image, "tag", _PYTHON, "sha256:" + "d" * 64, "k", True)
    prepared = PreparedEnvironment(image, recipe, baseline, snapshot)
    sandbox = DockerValidation(_CONFIG, python_image, recipe, run_id, store.root)
    checks = FixChecks(
        workspace,
        prepared,
        sandbox,
        store=store,
        run_id=run_id,
        quality=QualityConfig(),
        policy=PolicyConfig(),
        command_timeout_seconds=_CONFIG.command_timeout_seconds,
        seconds_left=budget.seconds_left,
        host_values=frozenset(),
    )
    new_test = (
        "@@\n         self.assertEqual(add(0, 0), 0)\n"
        "+\n+    def test_adds(self):\n+        self.assertEqual(add(1, 2), 3)\n"
    )
    agent = ScriptedProvider(
        turn("openai", Shell(f"python run_tests.py {_REPORT}")),
        turn(
            "openai",
            Raw("apply_patch", {"type": "update_file", "path": "test_calc.py", "diff": new_test}),
            Raw(
                "apply_patch",
                {
                    "type": "update_file",
                    "path": "calc.py",
                    "diff": "@@\n def add(a, b):\n-    return a - b\n+    return a + b\n",
                },
            ),
        ),
        turn("openai", Submit(_FIX)),
        turn("openai", Submit(_FIX)),
    )
    transcript = start_transcript(
        model="gpt-5.6-sol",
        effort="high",
        kind="agent",
        run_id=run_id,
        instructions=load_instructions("agent"),
        task="Fix issue #7: add(1, 2) returns -1.",
        host_values=frozenset(),
    )
    with SessionContainer(
        _CONFIG,
        image=python_image,
        workspace=workspace.path,
        run_id=run_id,
        store_root=store.root,
    ) as session:
        solver = Solver(
            transcript,
            checker=checks,
            provider=agent,
            budget=budget,
            store=store,
            host_values=frozenset(),
            tools=SessionTools(
                session,
                WorkspaceFiles(workspace.path),
                command_timeout_seconds=_CONFIG.command_timeout_seconds,
                seconds_left=budget.seconds_left,
                environment=recipe.env,
            ),
        )
        fixed = solver.run()

    assert isinstance(fixed, SubmittedFix), fixed
    result = checks.results[fixed.check.diff_sha256]
    assert result.passed, fixed.check.text
    red_green = result.red_green
    assert red_green is not None and red_green.status == "passed"
    assert red_green.reproduced == ["test_calc.AddTest::test_adds"]
    assert [run.kind for run in red_green.runs] == ["red", "green", "green", "green"]
    regression = result.regression
    assert regression is not None and regression.status == "passed" and regression.full_suite
    assert regression.runs[-1].passed == 2
    assert (checks.validated / "calc.py").read_text() == "def add(a, b):\n    return a + b\n"
    assert not workspace.path.with_name("repository.red").exists()

    blockers: list[JsonValue] = [
        {
            "category": "definite_bug",
            "path": "calc.py",
            "line": 2,
            "evidence": "add(2, 2) is not 5",
            "check_command": "python -c 'from calc import add; assert add(2, 2) == 5'",
            "fix_hint": "Return 5.",
        },
        {
            "category": "issue_not_fixed",
            "path": "calc.py",
            "line": 2,
            "evidence": "add still subtracts",
            # Passes with the fix, so the controller drops the blocker.
            "check_command": "python -c 'from calc import add; assert add(2, 2) == 4'",
            "fix_hint": "Add the arguments.",
        },
    ]
    review: dict[str, JsonValue] = {
        "verdict": "request_changes",
        "blockers": blockers,
        "notes": [],
        "no_test_needed": False,
        "summary": "The fix adds; one check disagrees.",
    }
    critic_provider = ScriptedProvider(
        turn("anthropic", Shell(f"python run_tests.py {_REPORT} && touch /workspace/scratch")),
        turn("anthropic", Submit(review, name="submit_review")),
    )
    critic = Critic(
        RunFacts(_issue(), _repository(), workspace.base_sha, recipe, baseline, None),
        sandbox,
        provider=critic_provider,
        model="claude-opus-5-5",
        budget=budget,
        store=store,
        host_values=frozenset(),
        command_timeout_seconds=_CONFIG.command_timeout_seconds,
    )

    outcome = critic.review(
        fixed, result, patch=extract_patch(workspace).text, validated=checks.validated
    )

    assert isinstance(outcome, CriticRound), outcome
    assert outcome.decision == "request_changes"
    assert [blocker.category for blocker in outcome.confirmed] == ["definite_bug"]
    assert [dropped.reason for dropped in outcome.dropped] == ["its check passes"]
    items = json.loads(
        "[" + ",".join((store.runs_dir / run_id / "critic-1.jsonl").read_text().splitlines()) + "]"
    )
    assert "test_calc.AddTest test_adds ok" in _texts(items)
    assert not (checks.validated / "scratch").exists()
    assert not list(checks.validated.parent.glob("repository.validation.*"))
    label = f"label=org.autocontribute.run={run_id}"
    leftovers = _docker("ps", "--all", "--quiet", "--filter", label)
    assert leftovers.returncode == 0 and leftovers.stdout.strip() == ""
