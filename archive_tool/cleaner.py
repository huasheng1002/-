"""广告文件删除。

规则：

- 只匹配文件名（basename），不匹配目录名；
- 子串匹配，使用 :meth:`str.casefold` 实现不区分大小写；
- 命中即删除文件，空目录一律保留；
- 单个文件删除失败记录警告，不中断处理。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Sequence


@dataclass
class CleanResult:
    """清理结果。"""

    removed: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def clean_ad_files(root: str, keywords: Sequence[str]) -> CleanResult:
    """递归删除解压目录中文件名含广告关键词的文件。"""
    result = CleanResult()
    folded = [keyword.casefold() for keyword in keywords if keyword.strip()]
    if not folded:
        return result

    for current, _dirnames, filenames in os.walk(root):
        for name in filenames:
            lowered = name.casefold()
            if not any(keyword in lowered for keyword in folded):
                continue
            full_path = os.path.join(current, name)
            relative = os.path.relpath(full_path, root).replace(os.sep, "/")
            try:
                os.remove(full_path)
                result.removed.append(relative)
            except OSError as exc:
                result.warnings.append("删除失败 {0}：{1}".format(relative, exc))
    return result
