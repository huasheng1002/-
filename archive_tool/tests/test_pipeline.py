"""端到端流水线测试（需要 bin/7z.exe，可用 APS_TEST_7Z 指定其他路径）。"""

from __future__ import annotations

import hashlib
import random
import tempfile
from pathlib import Path

import pytest

from archive_engine import SevenZipEngine
from conftest import HAS_7Z, SEVEN_ZIP

from helpers import (
    extract_with_password,
    list_without_password,
    make_archive,
    read_records,
    run_main,
    write_config,
    write_passwords,
    write_raw_zip,
)

pytestmark = pytest.mark.skipif(not HAS_7Z, reason="需要 7z.exe（bin/7z.exe 或 APS_TEST_7Z）")


def _prepare(tmp_path: Path):
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    output_dir = tmp_path / "out"
    return input_dir, output_dir


def test_zip_full_pipeline(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "a.zip"
    make_archive(
        archive,
        "zip",
        "old-pass",
        {
            "keep.txt": "keep",
            "广告.txt": "ad",
            "VPN.txt": "ad2",
            "empty/广告.txt": "ad3",
            "sub/keep2.txt": "k2",
        },
    )
    before = hashlib.sha256(archive.read_bytes()).hexdigest()

    notice = tmp_path / "notice.txt"
    notice.write_text("notice", encoding="utf-8")
    table = write_passwords(
        tmp_path / "passwords.yaml", exact={str(archive): ["wrong-pass", "old-pass"]}
    )
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
        add_files=[{"source": str(notice), "target_path": "sub/notice.txt"}],
    )

    assert run_main(config) == 0

    out_archive = output_dir / "a.zip"
    assert out_archive.is_file()
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == before  # 原包未被改动

    destination = tmp_path / "extracted"
    extract_with_password(out_archive, "new-pass", destination)
    assert (destination / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert not (destination / "广告.txt").exists()
    assert not (destination / "VPN.txt").exists()
    assert (destination / "sub" / "notice.txt").read_text(encoding="utf-8") == "notice"
    assert (destination / "empty").is_dir()  # 空目录保留

    records = read_records(tmp_path / "logs" / "process.log")
    assert len(records) == 1
    record = records[0]
    assert record["status"] == "SUCCESS"
    assert record["old_password"] == "old-pass"
    assert record["password_source"] == "exact"
    assert record["password_index"] == 2
    assert record["new_password"] == "new-pass"
    assert "广告.txt" in record["removed_files"]
    assert "sub/notice.txt" in record["added_files"]
    assert record["renamed"] is False
    assert record["output"] == str(out_archive)
    assert record["duration_ms"] >= 0


def test_7z_header_encryption(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "b.7z"
    make_archive(archive, "7z", "old-pass", {"keep.txt": "keep", "广告.exe": "bad"})

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
    )
    assert run_main(config) == 0

    out_archive = output_dir / "b.7z"
    assert out_archive.is_file()
    assert list_without_password(out_archive) != 0  # 文件名已加密

    destination = tmp_path / "extracted"
    extract_with_password(out_archive, "new-pass", destination)
    assert (destination / "keep.txt").is_file()
    assert not (destination / "广告.exe").exists()

    record = read_records(tmp_path / "logs" / "process.log")[0]
    assert record["password_source"] == "default"
    assert record["password_index"] == 1


def test_conflict_adds_copy_suffix(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    output_dir.mkdir()
    (output_dir / "a.zip").write_bytes(b"placeholder")
    archive = input_dir / "a.zip"
    make_archive(archive, "zip", "old-pass", {"keep.txt": "keep"})

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
    )
    assert run_main(config) == 0
    assert (output_dir / "a副本.zip").is_file()

    record = read_records(tmp_path / "logs" / "process.log")[0]
    assert record["renamed"] is True
    assert record["status"] == "SUCCESS"


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "a.zip"
    make_archive(archive, "zip", "old-pass", {"keep.txt": "keep"})

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
    )
    assert run_main(config, "--dry-run") == 0
    assert not (output_dir / "a.zip").exists()

    record = read_records(tmp_path / "logs" / "process.log")[0]
    assert record["status"] == "DRY_RUN"
    assert record["output"] is None
    assert record["old_password"] == "old-pass"


def test_password_miss_is_skipped(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "a.zip"
    make_archive(archive, "zip", "old-pass", {"keep.txt": "keep"})

    table = write_passwords(tmp_path / "passwords.yaml", default=["wrong-1", "wrong-2"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
    )
    assert run_main(config) == 1
    assert not (output_dir / "a.zip").exists()

    record = read_records(tmp_path / "logs" / "process.log")[0]
    assert record["status"] == "SKIPPED"
    assert "密码未命中" in str(record["error"])
    assert record["candidates"] == 2


def test_classic_split_zip_skipped(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "c.zip"
    make_archive(archive, "zip", "old-pass", {"keep.txt": "keep"})
    (input_dir / "c.z01").write_bytes(b"PK\x03\x04")

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
    )
    assert run_main(config) == 1
    assert not (output_dir / "c.zip").exists()

    record = read_records(tmp_path / "logs" / "process.log")[0]
    assert record["status"] == "SKIPPED"
    assert "分卷" in str(record["error"])


def test_7z_volume_processing(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    payload = random.Random(20261110).randbytes(60000)
    archive = input_dir / "vol.7z"
    first = make_archive(
        archive,
        "7z",
        "old-pass",
        {"payload.bin": payload, "keep.txt": "keep"},
        split="16k",
    )
    assert first.name == "vol.7z.001"
    assert (input_dir / "vol.7z.002").is_file()

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
    )
    assert run_main(config) == 0

    out_first = output_dir / "vol.7z.001"
    assert out_first.is_file()
    assert (output_dir / "vol.7z.002").is_file()

    destination = tmp_path / "extracted"
    extract_with_password(out_first, "new-pass", destination)
    assert (destination / "payload.bin").read_bytes() == payload
    assert (destination / "keep.txt").is_file()

    record = read_records(tmp_path / "logs" / "process.log")[0]
    assert record["volume"] is True
    assert record["output"] == str(out_first)


def test_gbk_filename_zip(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "gbk.zip"
    write_raw_zip(archive, [("中文.txt".encode("gbk"), b"hello")])

    table = write_passwords(tmp_path / "passwords.yaml", default=["unused"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
    )
    assert run_main(config) == 0

    destination = tmp_path / "extracted"
    extract_with_password(output_dir / "gbk.zip", "new-pass", destination)
    names = [item.name for item in destination.iterdir()]
    assert "中文.txt" in names


def test_zip_output_with_chinese_password(tmp_path: Path) -> None:
    """7-Zip 不能用非 ASCII 密码建 zip，走 pyzipper 兜底且 7z 可正常打开。"""
    pytest.importorskip("pyzipper")
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "a.zip"
    make_archive(archive, "zip", "old-pass", {"keep.txt": "keep"})

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
        new_password="新密码456",
    )
    assert run_main(config) == 0

    out_archive = output_dir / "a.zip"
    assert out_archive.is_file()
    destination = tmp_path / "extracted"
    extract_with_password(out_archive, "新密码456", destination)
    assert (destination / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_mcp_936_extraction_path(tmp_path: Path) -> None:
    """强制 -mcp=936 的路径能还原 GBK 来源文件名。"""
    archive = tmp_path / "gbk.zip"
    write_raw_zip(archive, [("中文.txt".encode("gbk"), b"hello")])

    engine = SevenZipEngine(str(SEVEN_ZIP), code_page=936, pass_via="arg")
    engine.probe()
    destination = tmp_path / "extracted"
    engine.extract(str(archive), str(destination), "unused", "zip")
    assert (destination / "中文.txt").is_file()


def test_failure_isolation_and_temp_cleanup(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    make_archive(input_dir / "good.zip", "zip", "old-pass", {"keep.txt": "keep"})
    (input_dir / "bad.zip").write_bytes(b"this is not a zip file")

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
    )

    temp_base = Path(tempfile.gettempdir()) / "archive_tool"
    before = {item.name for item in temp_base.iterdir()} if temp_base.is_dir() else set()
    assert run_main(config) == 1
    after = {item.name for item in temp_base.iterdir()} if temp_base.is_dir() else set()
    assert after - before == set()  # 临时目录已清理

    assert (output_dir / "good.zip").is_file()
    assert not (output_dir / "bad.zip").exists()

    records = read_records(tmp_path / "logs" / "process.log")
    statuses = {Path(str(record["source"])).name: record["status"] for record in records}
    assert statuses["bad.zip"] == "FAILED"
    assert statuses["good.zip"] == "SUCCESS"


def test_zip_fallback_engine_when_7z_missing(tmp_path: Path) -> None:
    """7z 不可用时，非分卷 zip 可走 pyzipper 备选引擎完成全流程。"""
    pytest.importorskip("pyzipper")
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "a.zip"
    make_archive(archive, "zip", "old-pass", {"keep.txt": "keep", "广告.txt": "ad"})

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
        seven_zip=str(tmp_path / "missing-7z.exe"),
        allow_zip_fallback=True,
    )
    assert run_main(config) == 0

    out_archive = output_dir / "a.zip"
    assert out_archive.is_file()
    destination = tmp_path / "extracted"
    extract_with_password(out_archive, "new-pass", destination)
    assert (destination / "keep.txt").is_file()
    assert not (destination / "广告.txt").exists()

    record = read_records(tmp_path / "logs" / "process.log")[0]
    assert record["status"] == "SUCCESS"


def test_stdin_fallback_and_masking(tmp_path: Path) -> None:
    input_dir, output_dir = _prepare(tmp_path)
    archive = input_dir / "a.zip"
    make_archive(archive, "zip", "old-pass", {"keep.txt": "keep"})

    table = write_passwords(tmp_path / "passwords.yaml", default=["old-pass"])
    config = write_config(
        tmp_path,
        input_paths=[str(input_dir)],
        output_dir=str(output_dir),
        table_file=str(table),
        pass_via="stdin",
        log_password=False,
    )
    assert run_main(config) == 0
    record = read_records(tmp_path / "logs" / "process.log")[0]
    assert record["status"] == "SUCCESS"
    assert record["old_password"] == "******"
    assert record["new_password"] == "******"
