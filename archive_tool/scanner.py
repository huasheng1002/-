"""输入扫描。

- 输入可以是文件或目录；``recursive`` 控制是否递归子目录；
- 只收集 ``extensions`` 中列出的后缀；
- ``.zip.001`` / ``.7z.001`` 视为分卷入口，仅首卷入列，同组其余卷不单独入列；
- 跳过输出目录、临时目录，避免把自身产物当成输入；
- 传统 ``.z01`` 分卷不做合并，标记为不支持并由上层记录 SKIPPED。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Sequence

_SPLIT_Z = re.compile(r"\.z\d{2,3}$", re.IGNORECASE)
_VOLUME_SUFFIXES = (".zip.001", ".7z.001")


@dataclass
class ArchiveTask:
    """一个待处理的压缩包。"""

    path: str
    kind: str  # zip | 7z | ""（不支持）
    root: str
    is_volume: bool = False
    volume_base: Optional[str] = None
    unsupported: Optional[str] = None

    @property
    def relative_path(self) -> str:
        """相对于扫描根目录的路径。"""
        return os.path.relpath(self.path, self.root)


def _is_under(path: str, parent: str) -> bool:
    try:
        child_norm = os.path.normcase(os.path.abspath(path))
        parent_norm = os.path.normcase(os.path.abspath(parent)).rstrip("\\/")
        if not parent_norm:
            return False
        return child_norm == parent_norm or child_norm.startswith(parent_norm + os.sep)
    except (ValueError, OSError):
        return False


def _classic_split_reason(path: str, kind: str) -> Optional[str]:
    lower = path.lower()
    if _SPLIT_Z.search(lower):
        return "不支持的传统分卷格式（.z01/.z02…），需人工预合并为标准 zip"
    if kind == "zip":
        stem = path[:-4]  # 去掉 .zip
        for candidate in (stem + ".z01", stem + ".Z01", stem + ".z001"):
            if os.path.isfile(candidate):
                return "检测到 .z01 分卷，属不支持的传统分卷 zip，需人工预合并"
    return None


def _build_task(path: str, root: str) -> ArchiveTask:
    lower = path.lower()
    is_volume = lower.endswith(_VOLUME_SUFFIXES)
    base = path[:-4] if is_volume else path  # 去掉 .001
    base_lower = base.lower()
    if base_lower.endswith(".zip"):
        kind = "zip"
    elif base_lower.endswith(".7z"):
        kind = "7z"
    else:
        kind = ""

    unsupported: Optional[str] = None
    if _SPLIT_Z.search(lower):
        unsupported = "不支持的传统分卷格式（.z01/.z02…），需人工预合并为标准 zip"
    elif kind:
        unsupported = _classic_split_reason(path, kind)
    else:
        extension = os.path.splitext(lower)[1] or path
        unsupported = "不支持的压缩格式：{0}".format(extension)

    return ArchiveTask(
        path=path,
        kind=kind,
        root=root,
        is_volume=is_volume,
        volume_base=base if is_volume else None,
        unsupported=unsupported,
    )


def task_for_path(path: str, root: Optional[str] = None) -> ArchiveTask:
    """为单个路径构造任务（供 ``--only`` 使用，不受后缀列表限制）。"""
    resolved = os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
    return _build_task(resolved, root or os.path.dirname(resolved))


def _iter_files(root: str, recursive: bool) -> Iterator[str]:
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if recursive:
                                stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            yield entry.path
                    except OSError:
                        continue
        except OSError:
            continue


def _matches_extension(name: str, extensions: Sequence[str]) -> bool:
    lower = name.casefold()
    return any(lower.endswith("." + extension) for extension in extensions)


def scan_inputs(
    paths: Iterable[str],
    *,
    recursive: bool,
    extensions: Sequence[str],
    skip_dirs: Sequence[str] = (),
) -> List[ArchiveTask]:
    """扫描输入路径，返回去重后的任务列表（按路径排序）。"""
    normalized_extensions = [item.strip().lower().lstrip(".") for item in extensions if item.strip()]
    skip = [os.path.abspath(item) for item in skip_dirs if item]
    tasks: Dict[str, ArchiveTask] = {}

    def add_task(candidate: str, root: str) -> None:
        if any(_is_under(candidate, skipped) for skipped in skip):
            return
        key = os.path.normcase(os.path.abspath(candidate))
        if key in tasks:
            return
        tasks[key] = _build_task(os.path.abspath(candidate), root)

    for raw in paths:
        path = os.path.abspath(os.path.expanduser(os.path.expandvars(raw)))
        if os.path.isfile(path):
            if _matches_extension(os.path.basename(path), normalized_extensions):
                add_task(path, os.path.dirname(path))
        elif os.path.isdir(path):
            for file_path in _iter_files(path, recursive):
                if _matches_extension(os.path.basename(file_path), normalized_extensions):
                    add_task(file_path, path)

    return sorted(tasks.values(), key=lambda task: os.path.normcase(task.path))
