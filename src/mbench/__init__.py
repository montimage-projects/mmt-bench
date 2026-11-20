"""mmt-bench: a tool-agnostic benchmark harness for network security engines."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mbench")
except PackageNotFoundError:  # pragma: no cover - only when run from a bare source tree
    __version__ = "0+unknown"

__all__ = ["__version__"]
