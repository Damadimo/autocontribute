from __future__ import annotations

from autocontribute.environment_ci import (
    CiJob,
    load_strings_yaml,
    matrix_values,
    shell_commands,
    single_invocation,
    substitute_expressions,
)


def _job(matrix: dict[str, tuple[str, ...]]) -> CiJob:
    return CiJob({}, matrix, (), {})


def test_workflow_yaml_keeps_versions_and_keys_as_written() -> None:
    document = load_strings_yaml("on: push\nmatrix:\n  python: [3.10, 3.9]\nempty:\n")

    assert document == {"on": "push", "matrix": {"python": ["3.10", "3.9"]}, "empty": ""}
    assert load_strings_yaml("key: [unclosed") is None
    # Tags construct nothing: the node is read as the plain sequence it is.
    assert load_strings_yaml("!!python/object/apply:os.system ['true']") == ["true"]


def test_matrix_templates_expand_into_every_matrix_value() -> None:
    job = _job({"go": ("17", "24"), "os": ("ubuntu",)})

    assert matrix_values(job, "1.${{ matrix.go }}.x") == ["1.17.x", "1.24.x"]
    assert matrix_values(job, "3.12\n3.13\n") == ["3.12", "3.13"]
    assert matrix_values(job, "${{ fromJSON(needs.setup.outputs.go) }}") == []
    assert matrix_values(job, "${{ matrix.missing }}") == []


def test_expressions_resolve_only_literal_environment_values() -> None:
    text = substitute_expressions(
        "${{ env.CARGO }} test ${{ env.FLAGS }} ${{ matrix.target }}",
        {"CARGO": "cargo", "FLAGS": ""},
    )

    assert shell_commands(text) == [["cargo", "test", "$__unresolved__"]]


def test_shell_commands_split_operators_and_drop_redirections_and_substitutions() -> None:
    script = """set -ex
if [ -z "$CI" ]; then scripts/check; fi
${PREFIX}coverage run -m pytest "$@" 2>&1 | tee log.txt
$(PYTHON) -m pip install \\
    -r requirements.txt
"""

    assert shell_commands(script) == [
        ["set", "-ex"],
        ["[", "-z", "$CI", "]"],
        ["scripts/check"],
        ["coverage", "run", "-m", "pytest", "$@"],
        ["tee", "log.txt"],
        ["python", "-m", "pip", "install", "-r", "requirements.txt"],
    ]


def test_single_invocation_strips_wrappers_down_to_the_program() -> None:
    def words(command: str) -> tuple[str, ...] | None:
        invocation = single_invocation(command)
        return None if invocation is None else invocation.words

    assert words("FOO=1 uv run --group test python -W error -m pytest -q") == ("pytest", "-q")
    assert words("xvfb-run -a npx --yes jest --ci") == ("jest", "--ci")
    assert words("venv/bin/pytest tests") == ("pytest", "tests")
    assert words("coverage run --source x -m pytest") == ("pytest",)
    assert words("richgo test ./...") == ("go", "test", "./...")
    assert words("pytest && ruff check .") is None
    invocation = single_invocation("uv run --extra fast --group test pytest")
    assert invocation is not None
    assert (invocation.uv_groups, invocation.uv_extras) == (("test",), ("fast",))
    assert single_invocation("python tests/runtests.py -v2") is not None
    assert single_invocation("python tests/runtests.py").runner == "python-script"  # type: ignore[union-attr]
