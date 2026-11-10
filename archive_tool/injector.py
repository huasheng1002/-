"""新增文件注入。

按配置把源文件复制到解压目录的指定相对路径：

- 父目录不存在时自动创建；
- 目标已存在时直接覆盖；
- 单条失败只记录错误，不中断其他条目。
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import List, Sequence

from config_loader import AddFile


@dataclass
class InjectResult:
    """注入结果。"""

    added: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _safe_join(root: str, relative: str) -> str:
    """把相对路径安全地拼到根目录下，拒绝越界。"""
    normalized = relative.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("非法的目标路径：{0}".format(relative))
    root_abs = os.path.abspath(root)
    target = os.path.abspath(os.path.join(root_abs, *parts))
    if os.path.normcase(os.path.commonpath([root_abs, target])) != os.path.normcase(root_abs):
        raise ValueError("目标路径越界：{0}".format(relative))
    return target


def inject_files(root: str, add_files: Sequence[AddFile]) -> InjectResult:
    """把配置的新增文件复制进解压目录。"""
    result = InjectResult()
    for item in add_files:
        try:
            destination = _safe_join(root, item.target_path)
            parent = os.path.dirname(destination)
            if parent:
                os.makedirs(parent, exist_ok=True)
            shutil.copy2(item.source, destination)
            result.added.append(item.target_path)
        except (OSError, ValueError) as exc:
            result.errors.append("{0}：{1}".format(item.target_path, exc))
    return result
