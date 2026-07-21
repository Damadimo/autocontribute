"""Quality-gated open source contribution automation."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("autocontribute")
except PackageNotFoundError:  # pragma: no cover - source tree without installation
    __version__ = "0.0.0"

__all__ = ["__version__"]
