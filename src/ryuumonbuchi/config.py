"""Startup configuration and Ghidra installation validation."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

import os
import platform
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final


class ConfigError(ValueError):
    """Raised when startup configuration or the selected installation is invalid."""


@dataclass(frozen=True, slots=True)
class GhidraInstallation:
    """Validated metadata for one Ghidra installation."""

    path: Path
    version: str
    java_min: int
    python_supported: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Immutable runtime limits and the validated Ghidra location."""

    ghidra_install_dir: Path
    max_heap_mb: int = 1024
    max_cpu: int = 2
    operation_timeout_seconds: int = 900
    max_import_bytes: int = 67_108_864
    max_response_bytes: int = 4_194_304
    max_log_tail_bytes: int = 65_536
    vm_args: tuple[str, ...] = ()
    classpaths: tuple[str, ...] = ()
    class_files: tuple[str, ...] = ()
    allow_export: bool = False
    allow_import_bytes: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "ghidra_install_dir",
            self.ghidra_install_dir.expanduser().resolve(),
        )
        _validate_limits(self.max_heap_mb, self.max_cpu, self.operation_timeout_seconds)
        _validate_positive_limit("max_response_bytes", self.max_response_bytes)
        _validate_positive_limit("max_log_tail_bytes", self.max_log_tail_bytes)
        _validate_positive_limit("max_import_bytes", self.max_import_bytes)


_DEFAULT_GHIDRA_DIR: Final = Path("/usr/share/ghidra")
_LIMIT_ENV_NAMES: Final = {
    "max_heap_mb": "RYUUMONBUCHI_MAX_HEAP_MB",
    "max_cpu": "RYUUMONBUCHI_MAX_CPU",
    "operation_timeout_seconds": "RYUUMONBUCHI_OPERATION_TIMEOUT_SECONDS",
    "max_import_bytes": "RYUUMONBUCHI_MAX_IMPORT_BYTES",
    "max_response_bytes": "RYUUMONBUCHI_MAX_RESPONSE_BYTES",
    "max_log_tail_bytes": "RYUUMONBUCHI_MAX_LOG_TAIL_BYTES",
}
_BOOL_ENV_NAMES: Final = {
    "allow_export": "RYUUMONBUCHI_ALLOW_EXPORT",
    "allow_import_bytes": "RYUUMONBUCHI_ALLOW_IMPORT_BYTES",
}


_TRUE_VALUES: Final = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES: Final = frozenset({"0", "false", "no", "off"})


def _bool_flag(
    name: str,
    cli_value: bool | None,
    environ: Mapping[str, str],
    default: bool,
) -> bool:
    if cli_value is not None:
        return cli_value
    raw = environ.get(_BOOL_ENV_NAMES[name])
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    message = f"{_BOOL_ENV_NAMES[name]} must be a boolean (1/0, true/false, yes/no, on/off)"
    raise ConfigError(message)


_VERSION_PATTERN: Final = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?$")


def _validate_positive_limit(name: str, value: int) -> None:
    if type(value) is not int or value < 1:
        message = f"{name} must be a positive integer"
        raise ConfigError(message)


def _validate_limits(max_heap_mb: int, max_cpu: int, timeout: int) -> None:
    if type(max_heap_mb) is not int or not 256 <= max_heap_mb <= 8192:
        message = "max_heap_mb must be between 256 and 8192 MiB"
        raise ConfigError(message)
    cpu_count = os.cpu_count() or 1
    if type(max_cpu) is not int or not 1 <= max_cpu <= cpu_count:
        message = f"max_cpu must be between 1 and {cpu_count}"
        raise ConfigError(message)
    if type(timeout) is not int or not 30 <= timeout <= 86400:
        message = "operation_timeout_seconds must be between 30 and 86400 seconds"
        raise ConfigError(message)


def _limit_value(
    name: str,
    cli_value: int | None,
    environ: Mapping[str, str],
    default: int,
) -> int:
    if cli_value is not None:
        return cli_value
    env_name = _LIMIT_ENV_NAMES[name]
    raw = environ.get(env_name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        message = f"{env_name} must be an integer"
        raise ConfigError(message) from exc


def _resolve_classpaths(
    cli_classpaths: list[str] | None, environ: Mapping[str, str]
) -> tuple[str, ...]:
    """Resolve classpath entries from CLI list and RYUUMONBUCHI_CLASSPATH env."""
    import os as _os

    entries: list[str] = []
    if cli_classpaths:
        entries.extend(cli_classpaths)
    env_cp = environ.get("RYUUMONBUCHI_CLASSPATH")
    if env_cp:
        entries.extend(env_cp.split(_os.pathsep))
    resolved = []
    for entry in entries:
        p = Path(entry).expanduser().resolve()
        if not p.exists():
            message = f"classpath entry does not exist: {entry}"
            raise ConfigError(message)
        resolved.append(str(p))
    return tuple(resolved)


def _resolve_class_files(
    cli_class_files: list[str] | None, environ: Mapping[str, str]
) -> tuple[str, ...]:
    """Resolve class file entries from CLI list and RYUUMONBUCHI_CLASS_FILES env."""
    import os as _os

    entries: list[str] = []
    if cli_class_files:
        entries.extend(cli_class_files)
    env_cf = environ.get("RYUUMONBUCHI_CLASS_FILES")
    if env_cf:
        entries.extend(env_cf.split(_os.pathsep))
    resolved = []
    for entry in entries:
        p = Path(entry).expanduser().resolve()
        if not p.exists():
            message = f"class file does not exist: {entry}"
            raise ConfigError(message)
        resolved.append(str(p))
    return tuple(resolved)


def _resolve_vm_args(cli_vmargs: list[str] | None, environ: Mapping[str, str]) -> tuple[str, ...]:
    """Parse VM arguments from CLI list and RYUUMONBUCHI_VMARGS env."""
    import shlex

    entries: list[str] = []
    if cli_vmargs:
        entries.extend(cli_vmargs)
    env_va = environ.get("RYUUMONBUCHI_VMARGS")
    if env_va:
        entries.extend(shlex.split(env_va))
    return tuple(entries)


def resolve_ghidra_install_dir(
    cli_value: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the installation only from CLI, environment, then the fixed default."""
    env = os.environ if environ is None else environ
    selected = (
        cli_value if cli_value is not None else env.get("GHIDRA_INSTALL_DIR", _DEFAULT_GHIDRA_DIR)
    )
    return Path(selected).expanduser().resolve()


def build_config(
    *,
    ghidra_install_dir: str | Path | None = None,
    max_heap_mb: int | None = None,
    max_cpu: int | None = None,
    operation_timeout_seconds: int | None = None,
    max_import_bytes: int | None = None,
    max_response_bytes: int | None = None,
    max_log_tail_bytes: int | None = None,
    allow_export: bool | None = None,
    allow_import_bytes: bool | None = None,
    classpaths: list[str] | None = None,
    class_files: list[str] | None = None,
    vm_args: list[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> AppConfig:
    """Build configuration using CLI-over-environment-over-default precedence."""

    env = os.environ if environ is None else environ
    return AppConfig(
        ghidra_install_dir=resolve_ghidra_install_dir(ghidra_install_dir, env),
        max_heap_mb=_limit_value("max_heap_mb", max_heap_mb, env, 1024),
        max_cpu=_limit_value("max_cpu", max_cpu, env, 2),
        operation_timeout_seconds=_limit_value(
            "operation_timeout_seconds", operation_timeout_seconds, env, 900
        ),
        max_import_bytes=_limit_value("max_import_bytes", max_import_bytes, env, 67_108_864),
        max_response_bytes=_limit_value("max_response_bytes", max_response_bytes, env, 4_194_304),
        max_log_tail_bytes=_limit_value("max_log_tail_bytes", max_log_tail_bytes, env, 65_536),
        vm_args=_resolve_vm_args(vm_args, env),
        classpaths=_resolve_classpaths(classpaths, env),
        class_files=_resolve_class_files(class_files, env),
        allow_export=_bool_flag("allow_export", allow_export, env, False),
        allow_import_bytes=_bool_flag("allow_import_bytes", allow_import_bytes, env, False),
    )


def _parse_properties(path: Path) -> dict[str, str]:
    properties: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        message = f"Cannot read Ghidra metadata: {path}"
        raise ConfigError(message) from exc
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        properties[key.strip()] = value.strip()
    return properties


def _parse_version(raw: str) -> tuple[int, int, int]:
    match = _VERSION_PATTERN.fullmatch(raw.strip())
    if match is None:
        message = f"Ghidra application.version is invalid: {raw!r}"
        raise ConfigError(message)
    parts = tuple(int(part or 0) for part in match.groups())
    return parts  # type: ignore[return-value]


def validate_ghidra_installation(path: str | Path) -> GhidraInstallation:
    """Validate the selected Ghidra layout and supported runtime metadata."""

    if platform.system() != "Linux":
        message = "Ryuumonbuchi requires a POSIX/Linux host for process isolation"
        raise ConfigError(message)
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        message = f"Ghidra installation does not exist: {resolved}"
        raise FileNotFoundError(message)
    if not resolved.is_dir():
        message = f"Ghidra installation is not a directory: {resolved}"
        raise ConfigError(message)

    required = (
        resolved / "Ghidra" / "application.properties",
        resolved / "Ghidra" / "Features" / "PyGhidra" / "lib" / "PyGhidra.jar",
        resolved / "support" / "analyzeHeadless",
    )
    for required_path in required:
        if not required_path.exists():
            message = f"Ghidra installation is missing required path: {required_path}"
            raise ConfigError(message)
    properties = _parse_properties(required[0])
    raw_version = properties.get("application.version")
    if raw_version is None:
        message = "Ghidra metadata is missing application.version"
        raise ConfigError(message)
    if _parse_version(raw_version) < (12, 0, 0):
        message = f"Ghidra version {raw_version} is unsupported; require 12.0 or newer"
        raise ConfigError(message)

    raw_java = properties.get("application.java.min")
    if raw_java is None or not raw_java.isdecimal():
        message = "Ghidra metadata application.java.min is invalid"
        raise ConfigError(message)
    java_min = int(raw_java)
    if java_min < 21:
        message = f"Ghidra requires Java {java_min}, but Java 21 or newer is required"
        raise ConfigError(message)

    raw_python = properties.get("application.python.supported")
    if raw_python is None:
        message = "Ghidra metadata is missing application.python.supported"
        raise ConfigError(message)
    python_supported = tuple(part.strip() for part in raw_python.split(",") if part.strip())
    running = f"{sys.version_info.major}.{sys.version_info.minor}"
    if running not in python_supported:
        message = f"Ghidra installation does not support Python {running}"
        raise ConfigError(message)
    return GhidraInstallation(resolved, raw_version, java_min, python_supported)


def validate_config(config: AppConfig) -> GhidraInstallation:
    """Validate an immutable configuration and return the selected installation metadata."""

    return validate_ghidra_installation(config.ghidra_install_dir)


def safe_descendant(path: Path, root: Path) -> bool:
    """Return whether a resolved path is inside the resolved root."""

    try:
        path.expanduser().resolve().relative_to(root.expanduser().resolve())
    except ValueError:
        return False
    return True


def current_python_version() -> str:
    """Return the interpreter version used by the MCP process."""

    return ".".join(str(part) for part in sys.version_info[:3])
