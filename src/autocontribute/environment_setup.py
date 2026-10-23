"""Building a repository's environment image from a recipe (DESIGN §5.2, map-sandbox.md §C.2).

Setup runs the recipe's install commands, which execute repository and dependency code, with
network access. So the setup container sits on an internal network whose only exit is the
allowlisting egress proxy, gets the proxy address only in each command's ``env -i`` list, and
mounts ``.git`` read-only. A root bootstrap installs system packages and hands /opt/ac to the
command user in a container of its own, the only one with capabilities back; every other step
runs as that user in a container made from the bootstrap's image. Afterwards host Git undoes
any change a patch would carry, the container is committed with only a label change, and
everything else is removed. Locally, an image whose label matches the recipe and cache key is
reused.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import tomllib
from collections.abc import Collection, Mapping
from configparser import ConfigParser
from configparser import Error as ConfigParserError
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from autocontribute.config import SandboxConfig
from autocontribute.environment_signals import RepositorySignals
from autocontribute.environments import TOOL_ROOT, EnvironmentRecipe
from autocontribute.exceptions import EnvironmentSetupError, RepositoryError
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import (
    SETUP_CAPABILITIES,
    EgressNetwork,
    ImageIdentity,
    SessionContainer,
    detect_docker_daemon_mode,
    docker_container_identity,
    inspect_image,
    remove_image,
    tag_image,
)
from autocontribute.workspace_files import CONTAINER_WORKSPACE

# Package registries, OS mirrors and GitHub (research-envsetup.md §(d), map-sandbox.md §C.2).
DEFAULT_ALLOWED_HOSTS: Final = frozenset(
    {
        "archive.ubuntu.com",
        "codeload.github.com",
        "crates.io",
        "deb.debian.org",
        "dl-cdn.alpinelinux.org",
        "files.pythonhosted.org",
        "github.com",
        "index.crates.io",
        "nodejs.org",
        "objects.githubusercontent.com",
        "plugins.gradle.org",
        "proxy.golang.org",
        "pypi.org",
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "repo.maven.apache.org",
        "rubygems.org",
        "security.debian.org",
        "services.gradle.org",
        "static.crates.io",
        "static.rust-lang.org",
        "sum.golang.org",
    }
)
IMAGE_LABEL: Final = "org.autocontribute.environment"
_IMAGE_REPOSITORY: Final = "autocontribute-env"
_SETUP_HOME: Final = f"{TOOL_ROOT}/home"
# Setup's output in the workspace that Git ignores (node_modules, target/, build/) is kept
# here in the image, so a reused image can put it back.
_WORKSPACE_ARCHIVE: Final = f"{TOOL_ROOT}/workspace-setup.tar"
_SETUP_PIDS_LIMIT: Final = 4_096
_LOG_TAIL_LINES: Final = 200
_IMAGE_NAME_PART: Final = re.compile(r"[^a-z0-9]+")
# The bootstrap needs CHOWN for /opt/ac; apt needs the rest.
_BOOTSTRAP_CAPABILITIES: Final = frozenset({"CHOWN"})
# A probe that the project is installed from the workspace, so the tests exercise the
# working tree rather than an installed copy (research-envsetup.md §B4).
_IMPORT_PROBE: Final = """
import importlib, importlib.metadata as metadata, json, sys
name = sys.argv[1]
try:
    distribution = metadata.distribution(name)
except metadata.PackageNotFoundError:
    sys.exit(f"the project {name} is not installed")
origin = json.loads(distribution.read_text("direct_url.json") or "{}")
editable = (origin.get("dir_info") or {}).get("editable")
if editable and origin.get("url", "").rstrip("/") == "file:///workspace":
    sys.exit(0)
module = name.lower().replace("-", "_").replace(".", "_")
try:
    location = getattr(importlib.import_module(module), "__file__", None) or ""
except Exception as error:
    sys.exit(f"the project {name} does not import as {module}: {error}")
if not location.startswith("/workspace/"):
    sys.exit(f"the project {name} imports from {location or 'nowhere'}, not /workspace")
"""


@dataclass(frozen=True, slots=True)
class EnvironmentImage:
    """An environment image and what it was built from, for run evidence (DESIGN §4.1)."""

    image_id: str
    tag: str
    base_image: str
    base_digest: str
    cache_key: str
    # Found locally with a matching label instead of being built in this run.
    reused: bool


class EnvironmentSetup:
    """Build environment images from recipes, or reuse matching ones."""

    def __init__(
        self,
        config: SandboxConfig,
        *,
        run_id: str,
        store_root: Path,
        docker_binary: str = "docker",
        allow_local_source: bool = False,
    ) -> None:
        self.config = config
        self.run_id = run_id
        self.store_root = store_root
        self.docker_binary = docker_binary
        self.allow_local_source = allow_local_source
        # Installs run more processes than tests do: compilers, package managers, builds.
        self._setup_config = config.model_copy(
            update={"pids_limit": max(config.pids_limit, _SETUP_PIDS_LIMIT)}
        )

    def reuse(
        self,
        workspace: RepositoryWorkspace,
        recipe: EnvironmentRecipe,
        *,
        base: ImageIdentity,
        cache_key: str,
    ) -> EnvironmentImage | None:
        """Prepare ``workspace`` with an image built earlier from the same recipe and key.

        Returns ``None`` when there is no such image or its workspace output cannot be put
        back; the caller then builds one.
        """

        tag = image_tag(recipe.repository, cache_key)
        found = inspect_image(tag, docker_binary=self.docker_binary)
        if found is None or found.labels.get(IMAGE_LABEL) != self._label(recipe, cache_key):
            return None
        self._fetch_git_metadata(workspace, recipe)
        with SessionContainer(
            self.config,
            image=found.image_id,
            workspace=workspace.path,
            run_id=self.run_id,
            store_root=self.store_root,
            docker_binary=self.docker_binary,
        ) as container:
            extracted = container.exec(
                f"if [ -f {_WORKSPACE_ARCHIVE} ]; then "
                f"tar -xf {_WORKSPACE_ARCHIVE} -C {CONTAINER_WORKSPACE}; fi",
                timeout_seconds=self.config.command_timeout_seconds,
            )
        # The archive holds ignored files only; anything else it put back is undone.
        workspace.restore_base()
        if extracted.infrastructure_failure is not None or not extracted.result.passed:
            return None
        return EnvironmentImage(
            found.image_id, tag, recipe.base_image, base.digest, cache_key, reused=True
        )

    def build(
        self,
        workspace: RepositoryWorkspace,
        recipe: EnvironmentRecipe,
        *,
        base: ImageIdentity,
        cache_key: str,
        allow_hosts: Collection[str],
        distribution: str | None,
    ) -> tuple[EnvironmentImage, EnvironmentRecipe]:
        """Run the recipe's setup in a fresh container on ``workspace`` and commit it.

        ``distribution`` names the Python project that must import from the workspace. Returns
        the image and the recipe with ``setup_dirty_paths`` filled in. Raises
        :class:`EnvironmentSetupError` when a step fails.
        """

        self._fetch_git_metadata(workspace, recipe)
        with EgressNetwork(
            allowed_hosts=DEFAULT_ALLOWED_HOSTS | set(allow_hosts),
            run_id=self.run_id,
            store_root=self.store_root,
            docker_binary=self.docker_binary,
        ) as network:
            online = proxy_variables(network.proxy_url)
            bootstrapped = self._bootstrap(workspace, recipe, base, network, online)
            try:
                # Repository and dependency install scripts run here, with no capability back.
                with SessionContainer(
                    self._setup_config,
                    image=bootstrapped,
                    workspace=workspace.path,
                    run_id=self.run_id,
                    store_root=self.store_root,
                    docker_binary=self.docker_binary,
                    network=network.network,
                    writable_root=True,
                ) as container:
                    setup_environment = {**recipe.env, "HOME": _SETUP_HOME, **online}
                    for command in recipe.setup_commands:
                        self._step(container, network, command, command, setup_environment)
                    if distribution is not None:
                        probe = shlex.join(["python", "-c", _IMPORT_PROBE, distribution])
                        self._step(container, network, "the import check", probe, recipe.env)
                    try:
                        dirty = workspace.restore_base()
                    except RepositoryError as exc:
                        raise EnvironmentSetupError(
                            f"Setup left changes that cannot be undone: {exc}"
                        ) from exc
                    archived = self._archive_ignored(container, workspace)
                    labels = {IMAGE_LABEL: self._label(recipe, cache_key)} if archived else {}
                    image_id = container.commit(labels)
            except BaseException:
                # A committed environment image keeps the bootstrap image as its parent;
                # without one, the bootstrap image is only waste.
                remove_image(bootstrapped, docker_binary=self.docker_binary)
                raise
        tag = image_tag(recipe.repository, cache_key)
        tag_image(image_id, tag, docker_binary=self.docker_binary)
        image = EnvironmentImage(
            image_id, tag, recipe.base_image, base.digest, cache_key, reused=False
        )
        return image, recipe.model_copy(update={"setup_dirty_paths": dirty})

    def _bootstrap(
        self,
        workspace: RepositoryWorkspace,
        recipe: EnvironmentRecipe,
        base: ImageIdentity,
        network: EgressNetwork,
        online: Mapping[str, str],
    ) -> str:
        """Run the root bootstrap in a container of its own and commit it as an image.

        Only this container gets capabilities back, and it runs nothing from the repository:
        the base image's own tools and Debian's packages. Returns the image ID.
        """

        capabilities = SETUP_CAPABILITIES if recipe.system_packages else _BOOTSTRAP_CAPABILITIES
        with SessionContainer(
            self._setup_config,
            image=base.image_id,
            workspace=workspace.path,
            run_id=self.run_id,
            store_root=self.store_root,
            docker_binary=self.docker_binary,
            network=network.network,
            writable_root=True,
            capabilities=capabilities,
        ) as container:
            self._step(
                container,
                network,
                "the root bootstrap",
                bootstrap_script(recipe.system_packages, container.command_user),
                online,
                as_root=True,
            )
            return container.commit({})

    def _step(
        self,
        container: SessionContainer,
        network: EgressNetwork,
        name: str,
        command: str,
        environment: Mapping[str, str],
        *,
        as_root: bool = False,
    ) -> None:
        outcome = container.exec(
            command,
            timeout_seconds=self.config.command_timeout_seconds,
            environment=environment,
            as_root=as_root,
        )
        result = outcome.result
        if outcome.infrastructure_failure is None and result.passed:
            return
        if outcome.infrastructure_failure is not None:
            reason = outcome.infrastructure_failure
        elif result.timed_out:
            reason = f"timed out after {self.config.command_timeout_seconds} s"
        else:
            reason = f"exited with {result.exit_code}"
        lines = f"{result.stdout}\n{result.stderr}".strip().splitlines()
        # Hosts the proxy refused often explain a failed download.
        lines += network.refused_requests()
        raise EnvironmentSetupError(
            f"Setup step {name} {reason}", log_tail="\n".join(lines[-_LOG_TAIL_LINES:])
        )

    def _archive_ignored(self, container: SessionContainer, workspace: RepositoryWorkspace) -> bool:
        """Keep setup's ignored workspace output in the image; False when it cannot be kept."""

        try:
            ignored = workspace.ignored_paths()
        except RepositoryError:
            return False
        if not ignored:
            return True
        if any("\n" in path for path in ignored):
            return False
        # A ./ prefix keeps tar from reading a name that starts with "-" as an option.
        listing = "".join(f"./{path.rstrip('/')}\n" for path in ignored)
        return container.pipe(
            f"tar -cf {_WORKSPACE_ARCHIVE} -C {CONTAINER_WORKSPACE} -T -",
            listing,
            timeout_seconds=self.config.command_timeout_seconds,
        )

    def _fetch_git_metadata(
        self, workspace: RepositoryWorkspace, recipe: EnvironmentRecipe
    ) -> None:
        try:
            if recipe.fetch_tags:
                workspace.fetch_tags(allow_local_source=self.allow_local_source)
            if recipe.fetch_submodules:
                workspace.fetch_submodules(allow_local_source=self.allow_local_source)
        except RepositoryError as exc:
            raise EnvironmentSetupError(f"Fetching Git tags or submodules failed: {exc}") from exc

    def _label(self, recipe: EnvironmentRecipe, cache_key: str) -> str:
        mode = detect_docker_daemon_mode(self.docker_binary)
        uid, gid = docker_container_identity(mode)
        return environment_label(recipe, cache_key=cache_key, command_user=f"{uid}:{gid}")


def environment_label(recipe: EnvironmentRecipe, *, cache_key: str, command_user: str) -> str:
    """Identify what an environment image was built from.

    The cache key covers the dependencies and the base image; the recipe's own setup and the
    uid that owns /opt/ac decide the rest.
    """

    built_from = recipe.model_dump(
        include={
            "repository",
            "base_image",
            "system_packages",
            "setup_commands",
            "env",
            "fetch_tags",
            "fetch_submodules",
        }
    )
    canonical = json.dumps(
        {**built_from, "cache_key": cache_key, "command_user": command_user},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def image_tag(repository: str, cache_key: str) -> str:
    """Name a repository's environment image, as ``autocontribute-env/<owner>__<repo>:<key>``."""

    parts = [
        _IMAGE_NAME_PART.sub("-", part).strip("-") or "x"
        for part in repository.lower().split("/", 1)
    ]
    return f"{_IMAGE_REPOSITORY}/{'__'.join(parts)}:{cache_key[:12]}"


def proxy_variables(proxy_url: str) -> dict[str, str]:
    """The variables that send a setup command's downloads through the egress proxy."""

    names = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
    return {
        **dict.fromkeys(names, proxy_url),
        # Yarn 2+ reads only its own settings.
        "YARN_HTTP_PROXY": proxy_url,
        "YARN_HTTPS_PROXY": proxy_url,
        "NO_PROXY": "",
        "no_proxy": "",
    }


def bootstrap_script(system_packages: Collection[str], command_user: str) -> str:
    """The root step: install missing system packages and give /opt/ac to the command user.

    Package names come from CI scripts and may not exist in Debian (Ubuntu-only names), so
    unknown ones are skipped instead of failing the install.
    """

    uid, _, gid = command_user.partition(":")
    if not (uid.isdigit() and gid.isdigit()):
        raise ValueError("command user must be numeric uid:gid")
    packages = " ".join(shlex.quote(package) for package in sorted(system_packages))
    return f"""set -e
missing=""
if [ -n "{packages}" ] && command -v apt-get >/dev/null 2>&1; then
  for package in {packages}; do
    dpkg-query -W -f='${{Status}}' "$package" 2>/dev/null | grep -q 'install ok installed' \\
      || missing="$missing $package"
  done
elif [ -n "{packages}" ]; then
  echo "no apt-get in the base image; system packages skipped: {packages}"
fi
if [ -n "$missing" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  available=""
  for package in $missing; do
    if apt-cache show "$package" >/dev/null 2>&1; then
      available="$available $package"
    else
      echo "skipping unknown system package $package"
    fi
  done
  if [ -n "$available" ]; then apt-get install -y -qq --no-install-recommends $available; fi
  rm -rf /var/lib/apt/lists/*
fi
mkdir -p {_SETUP_HOME}
chown -R {uid}:{gid} {TOOL_ROOT}
grep -q "^[^:]*:[^:]*:{uid}:" /etc/passwd \\
  || echo "autocontribute:x:{uid}:{gid}::{_SETUP_HOME}:/bin/sh" >> /etc/passwd
grep -q "^[^:]*:[^:]*:{gid}:" /etc/group || echo "autocontribute:x:{gid}:" >> /etc/group
if command -v git >/dev/null 2>&1; then git config --system --add safe.directory '*'; fi
"""


def python_distribution(signals: RepositorySignals) -> str | None:
    """Name the Python project the repository declares, for the import check; None if unknown."""

    try:
        pyproject = tomllib.loads(signals.files.get("pyproject.toml", ""))
    except tomllib.TOMLDecodeError:
        pyproject = {}
    project = pyproject.get("project")
    if isinstance(project, dict) and isinstance(project.get("name"), str):
        return str(project["name"])
    tool = pyproject.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict) and isinstance(poetry.get("name"), str):
        return str(poetry["name"])
    parser = ConfigParser(interpolation=None)
    try:
        parser.read_string(signals.files.get("setup.cfg", ""))
    except ConfigParserError:
        return None
    name = parser.get("metadata", "name", fallback="").strip()
    return name or None


__all__ = [
    "DEFAULT_ALLOWED_HOSTS",
    "IMAGE_LABEL",
    "EnvironmentImage",
    "EnvironmentSetup",
    "bootstrap_script",
    "environment_label",
    "image_tag",
    "proxy_variables",
    "python_distribution",
]
