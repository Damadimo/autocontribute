"""The recipe that builds and tests one repository's environment, and its cache key (DESIGN §5)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import Field, field_validator

from autocontribute.config import validate_environment_command, validate_image_reference
from autocontribute.domain import DomainModel

# Setup installs tools, homes and caches here: an image path that later containers keep, unlike
# /tmp, which they mount a tmpfs over. Test and agent containers get it as a writable volume.
TOOL_ROOT: Final = "/opt/ac"
RECIPE_SCHEMA_VERSION: Final = 1
# Bump when detection or setup would build a different environment from the same signals, so
# cached recipes and environment images made by the old logic stop matching.
SETUP_LOGIC_VERSION: Final = 1

Language = Literal["python", "javascript", "go", "rust", "other"]
TestFramework = Literal["pytest", "unittest", "jest", "vitest", "mocha", "go", "cargo", "other"]

_REPOSITORY: Final = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_VARIABLE_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DEBIAN_PACKAGE: Final = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
_SHA256_HEX: Final = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARCHITECTURE: Final = re.compile(r"^[a-z0-9][a-z0-9_./-]{0,63}$")
_GIT_SHA: Final = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class EnvironmentRecipe(DomainModel):
    """How to build one repository's test environment and run its tests (DESIGN §5.1)."""

    repository: str
    language: Language
    base_image: str
    # apt packages the root bootstrap step installs.
    system_packages: list[str]
    # Run with network, through the setup proxy, as the command uid.
    setup_commands: list[str]
    # Run offline before every test run.
    build_commands: list[str]
    # Runs offline: the full suite or the closest equivalent.
    test_command: str
    test_framework: TestFramework
    # Container path of the structured results the test command writes, in the format of
    # test_framework; None when only the exit code and output are available.
    test_report: str | None
    # Variables for every command, setup included. Commands run under `env -i`, so this
    # carries everything the image's own ENV would have set, PATH included.
    env: dict[str, str]
    # Added for the commands that run without network: build, test and agent commands.
    offline_env: dict[str, str]
    # Setup fetches tags first, for versions derived from Git (research-envsetup.md §B5).
    fetch_tags: bool
    fetch_submodules: bool
    # The full suite exceeds the time limit, so validation runs related tests only (§5.3).
    targeted: bool = False
    # Tracked files setup changed and new files it left that Git does not ignore; they are
    # restored before the snapshot so they never reach a patch (§5.2).
    setup_dirty_paths: list[str] = Field(default_factory=list)
    source: Literal["config", "cached", "detected", "agent"]
    # sha256 over the (path, object ID) list of the files the recipe depends on.
    dependency_digest: str

    @field_validator("repository")
    @classmethod
    def repository_is_a_full_name(cls, value: str) -> str:
        if not _REPOSITORY.fullmatch(value):
            raise ValueError("recipe repository must use owner/name syntax")
        return value

    @field_validator("base_image")
    @classmethod
    def base_image_is_a_single_reference(cls, value: str) -> str:
        return validate_image_reference(value)

    @field_validator("system_packages")
    @classmethod
    def system_packages_are_package_names(cls, values: list[str]) -> list[str]:
        invalid = [value for value in values if not _DEBIAN_PACKAGE.fullmatch(value)]
        if invalid:
            raise ValueError(f"system_packages must be Debian package names: {invalid}")
        return values

    @field_validator("setup_commands", "build_commands")
    @classmethod
    def commands_are_safe(cls, values: list[str]) -> list[str]:
        return [validate_environment_command(value) for value in values]

    @field_validator("test_command")
    @classmethod
    def test_command_is_safe(cls, value: str) -> str:
        return validate_environment_command(value)

    @field_validator("env", "offline_env")
    @classmethod
    def variables_are_plain(cls, values: dict[str, str]) -> dict[str, str]:
        for name, value in values.items():
            if not _VARIABLE_NAME.fullmatch(name) or "\0" in value:
                raise ValueError(f"recipe variable {name!r} is not a plain NAME=value pair")
        return values

    @field_validator("setup_dirty_paths")
    @classmethod
    def dirty_paths_are_relative(cls, values: list[str]) -> list[str]:
        for value in values:
            parts = PurePosixPath(value).parts
            if not value or value.startswith("/") or "\0" in value or ".." in parts:
                raise ValueError(f"setup_dirty_paths must be repository paths: {value!r}")
        return values

    @field_validator("dependency_digest")
    @classmethod
    def dependency_digest_is_sha256(cls, value: str) -> str:
        if not _SHA256_HEX.fullmatch(value):
            raise ValueError("dependency_digest must be a lowercase SHA-256 hex digest")
        return value


class EnvironmentBaseline(DomainModel):
    """The unmodified base's tests, run offline two or three times (DESIGN §5.3)."""

    base_sha: str
    exit_codes: list[int]
    durations_seconds: list[float]
    # False when the test command writes no per-test report, so the suite counts as one test.
    per_test: bool
    # The first run exceeded the time limit, so the suite was not run again.
    timed_out: bool
    collected: int
    # Passed in every run.
    pass_stable: list[str]
    # Failed or errored in every run; validation ignores them.
    fail_before: list[str]
    # Different results across runs, including missing from some; validation ignores them.
    flaky: list[str]
    skip: list[str]
    # The longest duration seen per test, for choosing what fits a time limit.
    test_durations: dict[str, float]

    @field_validator("base_sha")
    @classmethod
    def base_sha_is_a_commit(cls, value: str) -> str:
        if not _GIT_SHA.fullmatch(value):
            raise ValueError("base_sha must be a full lowercase commit SHA")
        return value


def dependency_digest(dependency_files: Sequence[tuple[str, str]]) -> str:
    """Hash the (path, object ID) list of the files an environment depends on."""

    canonical = json.dumps(sorted(dependency_files), separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def environment_cache_key(
    *, language: Language, arch: str, base_image_digest: str, dependency_digest: str
) -> str:
    """Return the key of a cached recipe and its environment image (DESIGN §5.6, §B11).

    A cached recipe is replayed only while the setup logic, the base image the tag resolved
    to, the machine architecture and every dependency file are what they were when it was
    built.
    """

    if not _ARCHITECTURE.fullmatch(arch):
        raise ValueError("arch must name a platform such as linux/amd64")
    if not _IMAGE_DIGEST.fullmatch(base_image_digest):
        raise ValueError("base_image_digest must be sha256:<64 lowercase hex digits>")
    if not _SHA256_HEX.fullmatch(dependency_digest):
        raise ValueError("dependency_digest must be a lowercase SHA-256 hex digest")
    canonical = json.dumps(
        {
            "recipe_schema": RECIPE_SCHEMA_VERSION,
            "setup_logic": SETUP_LOGIC_VERSION,
            "language": language,
            "arch": arch,
            "base_image_digest": base_image_digest,
            "dependencies": dependency_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "RECIPE_SCHEMA_VERSION",
    "SETUP_LOGIC_VERSION",
    "TOOL_ROOT",
    "EnvironmentBaseline",
    "EnvironmentRecipe",
    "Language",
    "TestFramework",
    "dependency_digest",
    "environment_cache_key",
]
