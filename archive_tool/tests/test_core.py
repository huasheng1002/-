"""核心模块单元测试（不依赖 7z.exe）。"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from archive_engine import has_mojibake
from cleaner import clean_ad_files
from config_loader import AddFile, ConfigError, load_config
from injector import inject_files
from output_namer import plan_output
from password_resolver import PasswordResolver, PasswordTableError
from scanner import scan_inputs, task_for_path

from helpers import make_tree, write_passwords


def _config_data(tmp_path: Path) -> dict:
    input_dir = tmp_path / "input"
    input_dir.mkdir(parents=True, exist_ok=True)
    add_file = tmp_path / "notice.txt"
    add_file.write_text("notice", encoding="utf-8")
    seven = tmp_path / "7z.exe"
    seven.write_bytes(b"")
    table = write_passwords(tmp_path / "passwords.yaml", default=["demo"])
    return {
        "input": {
            "paths": [str(input_dir)],
            "recursive": True,
            "extensions": ["zip", "7z", "zip.001", "7z.001"],
        },
        "password": {
            "table_file": str(table),
            "new_password": "new-pass",
            "pass_via": "stdin",
        },
        "ad_keywords": ["广告", "vpn"],
        "add_files": [{"source": str(add_file), "target_path": "notice.txt"}],
        "output": {
            "dir": str(tmp_path / "out"),
            "keep_relative_structure": True,
            "rename_on_conflict": "副本",
        },
        "archive": {
            "seven_zip_path": str(seven),
            "code_page": None,
            "sevenz_encrypt_header": True,
            "zip_aes": True,
        },
        "log": {
            "dir": str(tmp_path / "logs"),
            "file": "process.log",
            "level": "INFO",
            "log_password": True,
            "console": False,
        },
    }


def _write(tmp_path: Path, data: dict, name: str = "config.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path


def test_load_valid_config(tmp_path: Path) -> None:
    config = load_config(str(_write(tmp_path, _config_data(tmp_path))), dry_run=True)
    assert config.password.pass_via == "stdin"
    assert config.input.extensions == ["zip", "7z", "zip.001", "7z.001"]
    assert config.archive.sevenz_encrypt_header is True


def test_missing_section_reports_field(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    del data["password"]
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "password"


def test_missing_new_password(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    data["password"]["new_password"] = ""
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "password.new_password"


def test_invalid_pass_via(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    data["password"]["pass_via"] = "pipe"
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "password.pass_via"


def test_missing_input_path(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    data["input"]["paths"] = [str(tmp_path / "not-exist")]
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "input.paths"


def test_missing_add_source(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    data["add_files"] = [{"source": str(tmp_path / "gone.txt"), "target_path": "notice.txt"}]
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "add_files[0].source"


def test_target_path_traversal_rejected(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    data["add_files"] = [{"source": data["add_files"][0]["source"], "target_path": "../evil.txt"}]
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "add_files[0].target_path"


def test_rename_word_invalid_char(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    data["output"]["rename_on_conflict"] = "副本/"
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "output.rename_on_conflict"


def test_missing_seven_zip_requires_fallback(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    data["archive"]["seven_zip_path"] = str(tmp_path / "nope" / "7z.exe")
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "archive.seven_zip_path"

    data["archive"]["allow_zip_fallback"] = True
    config = load_config(str(_write(tmp_path, data, "fallback.yaml")), dry_run=True)
    assert config.archive.seven_zip_path == ""
    assert config.archive.seven_zip_error


def test_invalid_code_page(tmp_path: Path) -> None:
    data = _config_data(tmp_path)
    data["archive"]["code_page"] = True
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(_write(tmp_path, data)), dry_run=True)
    assert excinfo.value.field_name == "archive.code_page"


def test_password_resolver_exact_priority(tmp_path: Path) -> None:
    table = write_passwords(
        tmp_path / "passwords.yaml",
        exact={r"D:\input\A.ZIP": ["p1", "p2"]},
        default=["d1"],
    )
    resolver = PasswordResolver.from_file(str(table))
    candidates = resolver.candidates(r"d:/input/a.zip")
    assert [(item.password, item.source, item.index) for item in candidates] == [
        ("p1", "exact", 1),
        ("p2", "exact", 2),
    ]


def test_password_resolver_default_fallback(tmp_path: Path) -> None:
    table = write_passwords(tmp_path / "passwords.yaml", default=["d1", "d2"])
    resolver = PasswordResolver.from_file(str(table))
    candidates = resolver.candidates(str(tmp_path / "other.zip"))
    assert [(item.source, item.index) for item in candidates] == [("default", 1), ("default", 2)]


def test_password_resolver_numeric_password(tmp_path: Path) -> None:
    path = tmp_path / "passwords.yaml"
    path.write_text(yaml.safe_dump({"default": [123456]}), encoding="utf-8")
    resolver = PasswordResolver.from_file(str(path))
    assert resolver.candidates(str(tmp_path / "a.zip"))[0].password == "123456"


def test_password_table_bad_format(tmp_path: Path) -> None:
    path = tmp_path / "passwords.yaml"
    path.write_text(yaml.safe_dump({"files": ["not-a-map"]}), encoding="utf-8")
    with pytest.raises(PasswordTableError):
        PasswordResolver.from_file(str(path))


def test_scan_filters_extensions_and_volumes(tmp_path: Path) -> None:
    root = tmp_path / "input"
    (root / "sub").mkdir(parents=True)
    for name in ["a.zip", "b.7z", "c.txt", "sub/d.zip", "e.7z.001", "e.7z.002"]:
        (root / name).write_bytes(b"")
    output = tmp_path / "out"
    output.mkdir()
    (output / "skip.zip").write_bytes(b"")

    tasks = scan_inputs(
        [str(root)],
        recursive=True,
        extensions=["zip", "7z", "zip.001", "7z.001"],
        skip_dirs=[str(output)],
    )
    names = sorted(Path(task.path).name for task in tasks)
    assert names == ["a.zip", "b.7z", "d.zip", "e.7z.001"]
    volume = next(task for task in tasks if task.is_volume)
    assert volume.volume_base.lower().endswith("e.7z")


def test_scan_non_recursive(tmp_path: Path) -> None:
    root = tmp_path / "input"
    (root / "sub").mkdir(parents=True)
    (root / "a.zip").write_bytes(b"")
    (root / "sub" / "b.zip").write_bytes(b"")
    tasks = scan_inputs([str(root)], recursive=False, extensions=["zip"])
    assert [Path(task.path).name for task in tasks] == ["a.zip"]


def test_classic_split_zip_marked_unsupported(tmp_path: Path) -> None:
    archive = tmp_path / "c.zip"
    archive.write_bytes(b"")
    (tmp_path / "c.z01").write_bytes(b"")
    task = task_for_path(str(archive))
    assert task.unsupported and "分卷" in task.unsupported


def test_z01_extension_marked_unsupported(tmp_path: Path) -> None:
    path = tmp_path / "d.z01"
    path.write_bytes(b"")
    task = task_for_path(str(path))
    assert task.unsupported and "分卷" in task.unsupported


def test_cleaner_casefold_and_empty_dirs(tmp_path: Path) -> None:
    root = tmp_path / "extracted"
    make_tree(
        root,
        {
            "广告.txt": "a",
            "VPN.TXT": "b",
            "sub/推广.html": "c",
            "sub/keep.txt": "d",
            "keep.txt": "e",
        },
    )
    result = clean_ad_files(str(root), ["广告", "vpn", "推广"])
    assert set(result.removed) == {"广告.txt", "VPN.TXT", "sub/推广.html"}
    assert (root / "sub").is_dir()
    assert (root / "keep.txt").read_text(encoding="utf-8") == "e"
    assert not result.warnings


def test_injector_overwrite_and_nested(tmp_path: Path) -> None:
    root = tmp_path / "extracted"
    root.mkdir()
    (root / "notice.txt").write_text("old", encoding="utf-8")
    source = tmp_path / "notice.txt"
    source.write_text("new", encoding="utf-8")

    result = inject_files(
        str(root),
        [
            AddFile(source=str(source), target_path="notice.txt"),
            AddFile(source=str(source), target_path="config/setting.ini"),
            AddFile(source=str(tmp_path / "missing.txt"), target_path="missing.txt"),
        ],
    )
    assert result.added == ["notice.txt", "config/setting.ini"]
    assert (root / "notice.txt").read_text(encoding="utf-8") == "new"
    assert (root / "config" / "setting.ini").is_file()
    assert len(result.errors) == 1


def test_output_namer_conflicts(tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    plan = plan_output(str(output), "a.zip", is_volume=False)
    assert Path(plan.archive_path) == output / "a.zip"
    assert plan.renamed is False

    (output / "a.zip").write_bytes(b"")
    plan = plan_output(str(output), "a.zip", is_volume=False)
    assert Path(plan.archive_path).name == "a副本.zip"

    (output / "a副本.zip").write_bytes(b"")
    plan = plan_output(str(output), "a.zip", is_volume=False)
    assert Path(plan.archive_path).name == "a副本2.zip"


def test_output_namer_volume(tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    (output / "v.7z.001").write_bytes(b"")
    plan = plan_output(str(output), "v.7z.001", is_volume=True)
    assert Path(plan.archive_path).name == "v副本.7z"
    assert Path(plan.entry_path).name == "v副本.7z.001"
    assert plan.renamed is True


def test_mojibake_detector(tmp_path: Path) -> None:
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "╓╨╬─.txt").write_text("x", encoding="utf-8")
    assert has_mojibake(str(broken)) is True

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "中文.txt").write_text("x", encoding="utf-8")
    (clean / "café.txt").write_text("x", encoding="utf-8")
    assert has_mojibake(str(clean)) is False
