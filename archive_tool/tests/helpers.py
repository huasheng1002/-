"""测试辅助：构造压缩包、配置文件与读取日志。"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

from conftest import SEVEN_ZIP


def run_7z(args: Sequence[str], cwd: Optional[str] = None, timeout: int = 300):
    """直接调用 7z（测试夹具用）。"""
    return subprocess.run(
        [str(SEVEN_ZIP), *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def make_tree(root: Path, files: Mapping[str, object]) -> None:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(str(content), encoding="utf-8")


def make_archive(
    target: Path,
    kind: str,
    password: str,
    files: Mapping[str, str],
    *,
    mhe: bool = True,
    split: Optional[str] = None,
    aes: bool = True,
) -> Path:
    """用 7z 生成测试压缩包；分卷时返回首卷路径。"""
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    source = target.parent / "_build" / (target.name + "_src")
    shutil.rmtree(source, ignore_errors=True)
    source.mkdir(parents=True, exist_ok=True)
    make_tree(source, files)

    args = ["a", "-y"]
    if kind == "7z":
        args.append("-t7z")
        if mhe:
            args.append("-mhe=on")
    else:
        args.append("-tzip")
        if aes:
            args.append("-mem=AES256")
    if split:
        args.append("-v{0}".format(split))
    args.extend(["-p{0}".format(password), str(target), "*"])

    result = run_7z(args, cwd=str(source))
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    if split:
        return target.with_name(target.name + ".001")
    return target


def extract_with_password(archive: Path, password: str, destination: Path) -> None:
    result = run_7z(
        ["x", "-y", "-p{0}".format(password), "-o{0}".format(destination), str(archive)]
    )
    assert result.returncode == 0, (result.stdout + result.stderr).decode("utf-8", "replace")


def list_without_password(archive: Path) -> int:
    return run_7z(["l", str(archive)]).returncode


def write_raw_zip(path: Path, entries: Sequence[Tuple[bytes, bytes]]) -> None:
    """写入不设置 UTF-8 标志的 STORED zip（用于模拟 GBK 文件名来源）。"""
    locals_: List[bytes] = []
    centrals: List[bytes] = []
    offset = 0
    for name, data in entries:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        local = (
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                0,
                0,
                0,
                0,
                crc,
                len(data),
                len(data),
                len(name),
                0,
            )
            + name
            + data
        )
        central = (
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                0,
                0,
                0,
                0,
                crc,
                len(data),
                len(data),
                len(name),
                0,
                0,
                0,
                0,
                0,
                offset,
            )
            + name
        )
        locals_.append(local)
        centrals.append(central)
        offset += len(local)
    directory = b"".join(centrals)
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        len(entries),
        len(entries),
        len(directory),
        offset,
        0,
    )
    path.write_bytes(b"".join(locals_) + directory + end)


def write_passwords(
    path: Path,
    *,
    exact: Optional[Mapping[str, Sequence[str]]] = None,
    default: Optional[Sequence[str]] = None,
) -> Path:
    data: Dict[str, object] = {}
    if exact:
        data["files"] = {key: list(values) for key, values in exact.items()}
    if default:
        data["default"] = list(default)
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def write_config(
    tmp_path: Path,
    *,
    input_paths: Sequence[str],
    output_dir: str,
    table_file: str,
    add_files: Optional[Sequence[Mapping[str, str]]] = None,
    new_password: str = "new-pass",
    pass_via: str = "arg",
    extensions: Sequence[str] = ("zip", "7z", "zip.001", "7z.001"),
    keywords: Sequence[str] = ("广告", "vpn"),
    log_password: bool = True,
    code_page: Optional[int] = None,
    seven_zip: Optional[str] = None,
    allow_zip_fallback: bool = False,
) -> Path:
    data = {
        "input": {
            "paths": list(input_paths),
            "recursive": True,
            "extensions": list(extensions),
        },
        "password": {
            "table_file": str(table_file),
            "new_password": new_password,
            "pass_via": pass_via,
        },
        "ad_keywords": list(keywords),
        "add_files": list(add_files or []),
        "output": {
            "dir": str(output_dir),
            "keep_relative_structure": True,
            "rename_on_conflict": "副本",
        },
        "archive": {
            "seven_zip_path": str(seven_zip or SEVEN_ZIP),
            "allow_zip_fallback": allow_zip_fallback,
            "code_page": code_page,
            "sevenz_encrypt_header": True,
            "zip_aes": True,
        },
        "log": {
            "dir": str(tmp_path / "logs"),
            "file": "process.log",
            "level": "INFO",
            "log_password": log_password,
            "console": False,
        },
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path


def run_main(config_path: Path, *extra: str) -> int:
    from main import main

    return main(["--config", str(config_path), *extra])


def read_records(log_path: Path) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    if not log_path.is_file():
        return records
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("type") == "record":
            records.append(item)
    return records
