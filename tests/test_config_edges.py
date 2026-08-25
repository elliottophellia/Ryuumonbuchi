# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Config edge cases: validation errors, properties parsing, safe_descendant, python version."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
from pathlib import Path

import pytest

from ryuumonbuchi.config import (
    AppConfig,
    ConfigError,
    _parse_properties,
    _parse_version,
    _resolve_class_files,
    _resolve_classpaths,
    _resolve_vm_args,
    _validate_positive_limit,
    build_config,
    current_python_version,
    safe_descendant,
    validate_ghidra_installation,
)


def test_validate_positive_limit_rejects_zero() -> None:
    with pytest.raises(ConfigError, match="positive integer"):
        _validate_positive_limit("test", 0)


def test_validate_positive_limit_rejects_negative() -> None:
    with pytest.raises(ConfigError, match="positive integer"):
        _validate_positive_limit("test", -1)


def test_validate_positive_limit_rejects_non_int() -> None:
    with pytest.raises(ConfigError):
        _validate_positive_limit("test", "x")  # type: ignore[arg-type]


def test_validate_limits_heap_too_small(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="max_heap_mb"):
        build_config(ghidra_install_dir=str(fake_ghidra), max_heap_mb=128)


def test_validate_limits_heap_too_large(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="max_heap_mb"):
        build_config(ghidra_install_dir=str(fake_ghidra), max_heap_mb=99999)


def test_validate_limits_cpu_zero(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="max_cpu"):
        build_config(ghidra_install_dir=str(fake_ghidra), max_cpu=0)


def test_validate_limits_cpu_too_large(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="max_cpu"):
        build_config(ghidra_install_dir=str(fake_ghidra), max_cpu=9999)


def test_validate_limits_timeout_too_short(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="operation_timeout_seconds"):
        build_config(ghidra_install_dir=str(fake_ghidra), operation_timeout_seconds=10)


def test_validate_limits_timeout_too_long(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="operation_timeout_seconds"):
        build_config(ghidra_install_dir=str(fake_ghidra), operation_timeout_seconds=100000)


def test_validate_positive_limit_rejects_response_bytes_zero(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError):
        AppConfig(ghidra_install_dir=fake_ghidra, max_response_bytes=0)


def test_validate_positive_limit_rejects_import_bytes_zero(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError):
        AppConfig(ghidra_install_dir=fake_ghidra, max_import_bytes=0)


def test_validate_positive_limit_rejects_log_tail_bytes_zero(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError):
        AppConfig(ghidra_install_dir=fake_ghidra, max_log_tail_bytes=0)


def test_limit_value_non_integer_env(fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RYUUMONBUCHI_MAX_HEAP_MB", "not_a_number")
    with pytest.raises(ConfigError, match="must be an integer"):
        build_config(ghidra_install_dir=str(fake_ghidra), environ=dict(__import__("os").environ))


def test_env_class_files(
    fake_ghidra: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cf = tmp_path / "Test.class"
    cf.touch()
    monkeypatch.setenv("RYUUMONBUCHI_CLASS_FILES", str(cf))
    config = build_config(
        ghidra_install_dir=str(fake_ghidra),
        environ=dict(__import__("os").environ),
    )
    assert str(cf.resolve()) in config.class_files


def test_resolve_class_files_rejects_nonexistent() -> None:
    with pytest.raises(ConfigError):
        _resolve_class_files(["/nonexistent/Test.class"], {})


def test_resolve_classpaths_rejects_nonexistent() -> None:
    with pytest.raises(ConfigError):
        _resolve_classpaths(["/nonexistent/path"], {})


def test_resolve_vm_args_empty() -> None:
    assert _resolve_vm_args(None, {}) == ()


def test_resolve_vm_args_cli_only() -> None:
    assert _resolve_vm_args(["-Dx=1"], {}) == ("-Dx=1",)


def test_resolve_vm_args_env_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RYUUMONBUCHI_VMARGS", "-Da=1 -Db=2")
    assert _resolve_vm_args(None, dict(__import__("os").environ)) == ("-Da=1", "-Db=2")


def test_resolve_vm_args_both() -> None:
    result = _resolve_vm_args(["-Dcli=1"], {"RYUUMONBUCHI_VMARGS": "-Denv=1"})
    assert "-Dcli=1" in result
    assert "-Denv=1" in result


def test_parse_properties_success(tmp_path: Path) -> None:
    props = tmp_path / "app.properties"
    props.write_text("a=1\nb=2\n# comment\n\nc=hello world\n")
    result = _parse_properties(props)
    assert result == {"a": "1", "b": "2", "c": "hello world"}


def test_parse_properties_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Cannot read"):
        _parse_properties(tmp_path / "nonexistent.properties")


def test_parse_version_valid() -> None:
    assert _parse_version("12.0.4") == (12, 0, 4)
    assert _parse_version("12.0") == (12, 0, 0)
    assert _parse_version("12.1.0-SNAPSHOT") == (12, 1, 0)


def test_parse_version_invalid() -> None:
    with pytest.raises(ConfigError, match="invalid"):
        _parse_version("abc")


def test_validate_ghidra_version_too_old(tmp_path: Path) -> None:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.version=11.3.2\n"
        "application.java.min=21\n"
        "application.python.supported=3.13,3.12\n",
    )
    (root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar").touch()
    (root / "support/analyzeHeadless").touch()
    with pytest.raises(ConfigError, match="unsupported"):
        validate_ghidra_installation(root)


def test_validate_ghidra_missing_version(tmp_path: Path) -> None:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.java.min=21\napplication.python.supported=3.13,3.12\n",
    )
    (root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar").touch()
    (root / "support/analyzeHeadless").touch()
    with pytest.raises(ConfigError, match="missing application.version"):
        validate_ghidra_installation(root)


def test_validate_ghidra_java_min_too_low(tmp_path: Path) -> None:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.version=12.0.4\n"
        "application.java.min=17\n"
        "application.python.supported=3.13,3.12\n",
    )
    (root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar").touch()
    (root / "support/analyzeHeadless").touch()
    with pytest.raises(ConfigError, match="Java 21"):
        validate_ghidra_installation(root)


def test_validate_ghidra_python_unsupported(tmp_path: Path) -> None:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.version=12.0.4\napplication.java.min=21\napplication.python.supported=3.12\n",
    )
    (root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar").touch()
    (root / "support/analyzeHeadless").touch()
    with pytest.raises(ConfigError, match="Python 3.13"):
        validate_ghidra_installation(root)


def test_validate_ghidra_missing_python_supported(tmp_path: Path) -> None:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.version=12.0.4\napplication.java.min=21\n",
    )
    (root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar").touch()
    (root / "support/analyzeHeadless").touch()
    with pytest.raises(ConfigError, match="missing application.python.supported"):
        validate_ghidra_installation(root)


def test_validate_ghidra_invalid_java_min(tmp_path: Path) -> None:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.version=12.0.4\n"
        "application.java.min=notanumber\n"
        "application.python.supported=3.13,3.12\n",
    )
    (root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar").touch()
    (root / "support/analyzeHeadless").touch()
    with pytest.raises(ConfigError, match="application.java.min is invalid"):
        validate_ghidra_installation(root)


def test_validate_ghidra_not_directory(tmp_path: Path) -> None:
    fake = tmp_path / "notadir"
    fake.write_text("test")
    with pytest.raises(ConfigError, match="not a directory"):
        validate_ghidra_installation(fake)


def test_validate_ghidra_missing_required_path(tmp_path: Path) -> None:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.version=12.0.4\n"
        "application.java.min=21\n"
        "application.python.supported=3.13,3.12\n",
    )
    # Missing PyGhidra.jar
    (root / "support/analyzeHeadless").touch()
    with pytest.raises(ConfigError, match="missing required path"):
        validate_ghidra_installation(root)


def test_safe_descendant_inside(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    child = root / "child"
    child.mkdir()
    assert safe_descendant(child, root) is True


def test_safe_descendant_outside(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    assert safe_descendant(other, root) is False


def test_current_python_version() -> None:
    version = current_python_version()
    parts = version.split(".")
    assert len(parts) == 3
    assert int(parts[0]) == 3
    assert int(parts[1]) == 13
