# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Config: classpaths, vmargs, class-files, timeout bounds, removed gates."""

from __future__ import annotations

from pathlib import Path

import pytest

from ryuumonbuchi.config import (
    ConfigError,
    build_config,
    resolve_ghidra_install_dir,
    validate_config,
)


def test_build_config_defaults(fake_ghidra: Path) -> None:
    config = build_config(ghidra_install_dir=str(fake_ghidra))
    assert config.max_heap_mb == 1024
    assert config.max_cpu == 2
    assert config.operation_timeout_seconds == 900
    assert config.max_import_bytes == 67_108_864
    assert config.max_response_bytes == 4_194_304
    assert config.max_log_tail_bytes == 65_536
    assert config.vm_args == ()
    assert config.classpaths == ()
    assert config.class_files == ()


def test_config_defaults_deny_export_and_import(fake_ghidra: Path) -> None:
    config = build_config(ghidra_install_dir=str(fake_ghidra))
    assert config.allow_export is False
    assert config.allow_import_bytes is False



def test_config_allow_export_env_true(fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RYUUMONBUCHI_ALLOW_EXPORT", "1")
    config = build_config(ghidra_install_dir=str(fake_ghidra))
    assert config.allow_export is True


def test_config_allow_export_env_false(fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RYUUMONBUCHI_ALLOW_EXPORT", "no")
    config = build_config(ghidra_install_dir=str(fake_ghidra))
    assert config.allow_export is False


def test_config_allow_import_bytes_env_true(
    fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RYUUMONBUCHI_ALLOW_IMPORT_BYTES", "true")
    config = build_config(ghidra_install_dir=str(fake_ghidra))
    assert config.allow_import_bytes is True


def test_config_allow_export_cli_wins(fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RYUUMONBUCHI_ALLOW_EXPORT", "0")
    config = build_config(ghidra_install_dir=str(fake_ghidra), allow_export=True)
    assert config.allow_export is True


def test_config_allow_flag_rejects_invalid(fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RYUUMONBUCHI_ALLOW_EXPORT", "maybe")
    with pytest.raises(ConfigError, match="must be a boolean"):
        build_config(ghidra_install_dir=str(fake_ghidra))


def test_timeout_upper_bound_86400(fake_ghidra: Path) -> None:
    config = build_config(
        ghidra_install_dir=str(fake_ghidra),
        operation_timeout_seconds=86400,
    )
    assert config.operation_timeout_seconds == 86400


def test_timeout_rejects_above_86400(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError):
        build_config(
            ghidra_install_dir=str(fake_ghidra),
            operation_timeout_seconds=86401,
        )


def test_classpaths_resolved(fake_ghidra: Path, tmp_path: Path) -> None:
    cp_dir = tmp_path / "lib"
    cp_dir.mkdir()
    config = build_config(
        ghidra_install_dir=str(fake_ghidra),
        classpaths=[str(cp_dir)],
    )
    assert str(cp_dir.resolve()) in config.classpaths


def test_class_files_resolved(fake_ghidra: Path, tmp_path: Path) -> None:
    cf = tmp_path / "Test.class"
    cf.touch()
    config = build_config(
        ghidra_install_dir=str(fake_ghidra),
        class_files=[str(cf)],
    )
    assert str(cf.resolve()) in config.class_files


def test_vm_args_parsed(fake_ghidra: Path) -> None:
    config = build_config(
        ghidra_install_dir=str(fake_ghidra),
        vm_args=["-Dfoo=bar", "-Dbaz=qux"],
    )
    assert "-Dfoo=bar" in config.vm_args
    assert "-Dbaz=qux" in config.vm_args


def test_classpath_rejects_nonexistent(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError):
        build_config(
            ghidra_install_dir=str(fake_ghidra),
            classpaths=["/nonexistent/path"],
        )


def test_class_file_rejects_nonexistent(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError):
        build_config(
            ghidra_install_dir=str(fake_ghidra),
            class_files=["/nonexistent/Test.class"],
        )


def test_env_classpath(fake_ghidra: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cp_dir = tmp_path / "envlib"
    cp_dir.mkdir()
    monkeypatch.setenv("RYUUMONBUCHI_CLASSPATH", str(cp_dir))
    config = build_config(
        ghidra_install_dir=str(fake_ghidra),
        environ=dict(__import__("os").environ),
    )
    assert str(cp_dir.resolve()) in config.classpaths


def test_env_vmargs(fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RYUUMONBUCHI_VMARGS", "-Dtest=true -Dother=false")
    config = build_config(
        ghidra_install_dir=str(fake_ghidra),
        environ=dict(__import__("os").environ),
    )
    assert "-Dtest=true" in config.vm_args
    assert "-Dother=false" in config.vm_args


def test_resolve_ghidra_install_dir_env(monkeypatch: pytest.MonkeyPatch, fake_ghidra: Path) -> None:
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(fake_ghidra))
    resolved = resolve_ghidra_install_dir(environ=dict(__import__("os").environ))
    assert resolved == fake_ghidra.resolve()


def test_validate_config(fake_ghidra: Path) -> None:
    config = build_config(ghidra_install_dir=str(fake_ghidra))
    installation = validate_config(config)
    assert installation.version == "12.0.4"
    assert installation.java_min == 21
