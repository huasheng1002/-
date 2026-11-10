"""输出命名。

压缩前即确定最终路径，不依赖 7z 的覆盖行为：

- 默认输出 ``输出目录/原文件名``（相对结构由上层计算）；
- 已存在时依次尝试 ``原名副本.扩展名``、``原名副本2.扩展名``……
- 分卷输入按 ``.001`` 入口命名，冲突检查覆盖同组所有卷。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass
class OutputPlan:
    """输出计划。"""

    archive_path: str  # 传给 7z 的路径；分卷时不带 .001
    entry_path: str  # 最终对外路径；分卷时为 .001
    renamed: bool


def _volume_exists(base_path: str) -> bool:
    if os.path.exists(base_path):
        return True
    folder = os.path.dirname(base_path)
    if not folder or not os.path.isdir(folder):
        return False
    pattern = re.compile(
        "^" + re.escape(os.path.basename(base_path)) + r"\.\d{3}$", re.IGNORECASE
    )
    try:
        return any(pattern.match(entry.name) for entry in os.scandir(folder))
    except OSError:
        return False


def _with_rename(base_path: str, word: str, counter: int) -> str:
    stem, extension = os.path.splitext(base_path)
    suffix = word if counter <= 1 else "{0}{1}".format(word, counter)
    return "{0}{1}{2}".format(stem, suffix, extension)


def plan_output(
    output_dir: str,
    relative_path: str,
    *,
    is_volume: bool,
    rename_word: str = "副本",
) -> OutputPlan:
    """计算不冲突的输出路径。``relative_path`` 由调用方决定是否保留目录结构。"""
    relative = relative_path
    if is_volume and relative.lower().endswith(".001"):
        relative = relative[:-4]

    base_path = os.path.abspath(os.path.join(output_dir, relative))
    candidate = base_path
    counter = 0

    def conflict(path: str) -> bool:
        return _volume_exists(path) if is_volume else os.path.exists(path)

    while conflict(candidate):
        counter += 1
        candidate = _with_rename(base_path, rename_word, counter)

    entry = candidate + ".001" if is_volume else candidate
    return OutputPlan(archive_path=candidate, entry_path=entry, renamed=counter > 0)
