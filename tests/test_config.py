# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

from __future__ import annotations

from pathlib import Path

import pytest

from ryuumonbuchi.config import (
    AppConfig,
    ConfigError,
    build_config,
    safe_descendant,
    validate_ghidra_installation,
)


def test_cli_environment_default_precedence(fake_ghidra: Path) -> None:
    config = build_config(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=512,
        max_cpu=1,
        operation_timeout_seconds=60,
        environ={
            "GHIDRA_INSTALL_DIR": "/ignored",
            "RYUUMONBUCHI_MAX_HEAP_MB": "256",
            "RYUUMONBUCHI_MAX_CPU": "1",
            "RYUUMONBUCHI_OPERATION_TIMEOUT_SECONDS": "30",
        },
    )
    assert config.ghidra_install_dir == fake_ghidra.resolve()
    assert config.max_heap_mb == 512
    assert config.operation_timeout_seconds == 60


def test_missing_installation_has_exact_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(FileNotFoundError, match=f"Ghidra installation does not exist: {missing}"):
        validate_ghidra_installation(missing)


def test_invalid_limits_are_rejected(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="max_heap_mb"):
        AppConfig(fake_ghidra, max_heap_mb=255, max_cpu=1, operation_timeout_seconds=30)
    with pytest.raises(ConfigError, match="operation_timeout_seconds"):
        AppConfig(fake_ghidra, max_heap_mb=256, max_cpu=1, operation_timeout_seconds=29)


def test_safe_descendant_is_component_aware(tmp_path: Path) -> None:
    root = tmp_path / "root"
    child = root / "nested" / "file"
    sibling = tmp_path / "root-other" / "file"
    assert safe_descendant(child, root)
    assert not safe_descendant(sibling, root)


def test_boolean_env_flags_cli_over_env(fake_ghidra: Path) -> None:
    config = build_config(
        ghidra_install_dir=fake_ghidra,
        allow_export=False,
        environ={"RYUUMONBUCHI_ALLOW_EXPORT": "1", "RYUUMONBUCHI_ALLOW_IMPORT_BYTES": "0"},
    )
    assert not config.allow_export
    assert not config.allow_import_bytes


def test_boolean_env_parsing_variants(fake_ghidra: Path) -> None:
    config = build_config(
        ghidra_install_dir=fake_ghidra,
        environ={"RYUUMONBUCHI_ALLOW_EXPORT": " off ", "RYUUMONBUCHI_ALLOW_IMPORT_BYTES": "ON"},
    )
    assert not config.allow_export
    assert config.allow_import_bytes


def test_boolean_env_invalid_value_rejected(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="RYUUMONBUCHI_ALLOW_EXPORT must be a boolean"):
        build_config(
            ghidra_install_dir=fake_ghidra,
            environ={"RYUUMONBUCHI_ALLOW_EXPORT": "maybe"},
        )


def test_max_import_bytes_env_and_validation(fake_ghidra: Path) -> None:
    config = build_config(
        ghidra_install_dir=fake_ghidra,
        environ={"RYUUMONBUCHI_MAX_IMPORT_BYTES": "1024"},
    )
    assert config.max_import_bytes == 1024
    with pytest.raises(ConfigError, match="RYUUMONBUCHI_MAX_IMPORT_BYTES must be an integer"):
        build_config(
            ghidra_install_dir=fake_ghidra,
            environ={"RYUUMONBUCHI_MAX_IMPORT_BYTES": "lots"},
        )
    with pytest.raises(ConfigError, match="max_import_bytes"):
        AppConfig(fake_ghidra, max_import_bytes=0)
