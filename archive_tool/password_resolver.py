"""密码表解析与优先级。

解析规则（严格按任务书实现）：

1. 路径规范化：统一分隔符、绝对化、按 Windows 规则大小写不敏感；
2. ``files`` 中存在精确匹配键时，按该列表顺序尝试，来源记为 ``exact``；
3. 否则使用 ``default`` 列表顺序尝试，来源记为 ``default``；
4. 序号从 1 开始，用于日志记录命中优先级。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping

import yaml


class PasswordTableError(Exception):
    """密码表缺失或格式错误（入口退出码 2）。"""


@dataclass(frozen=True)
class PasswordCandidate:
    """一个候选密码。"""

    password: str
    source: str  # exact | default
    index: int  # 从 1 开始


def normalize_path(path: str) -> str:
    """路径规范化：绝对路径 + 统一分隔符 + Windows 大小写不敏感。"""
    return os.path.normcase(os.path.normpath(os.path.abspath(os.path.expanduser(path))))


def _password_list(values: Any, field_name: str) -> List[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise PasswordTableError("{0} 必须是列表".format(field_name))
    result: List[str] = []
    for index, item in enumerate(values):
        if isinstance(item, bool) or item is None:
            raise PasswordTableError(
                "{0}[{1}] 必须是字符串或数字".format(field_name, index)
            )
        if isinstance(item, (int, float)):
            text = str(item)
        elif isinstance(item, str):
            text = item
        else:
            raise PasswordTableError(
                "{0}[{1}] 必须是字符串或数字".format(field_name, index)
            )
        if text.strip():
            result.append(text)
    return result


class PasswordResolver:
    """按文件路径解析候选密码列表。"""

    def __init__(self, exact: Dict[str, List[str]], defaults: List[str]) -> None:
        self._exact = exact
        self._defaults = defaults

    @classmethod
    def from_file(cls, path: str) -> "PasswordResolver":
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                data = yaml.safe_load(handle)
        except OSError as exc:
            raise PasswordTableError("无法读取密码表：{0}".format(exc)) from exc
        except yaml.YAMLError as exc:
            raise PasswordTableError("密码表 YAML 解析失败：{0}".format(exc)) from exc
        if data is None:
            data = {}
        if not isinstance(data, Mapping):
            raise PasswordTableError("密码表根节点必须是对象")

        files_raw = data.get("files") or {}
        if not isinstance(files_raw, Mapping):
            raise PasswordTableError("files 必须是映射（路径 -> 密码列表）")
        exact: Dict[str, List[str]] = {}
        for key, values in files_raw.items():
            if not isinstance(key, str) or not key.strip():
                raise PasswordTableError("files 的键必须是文件路径字符串")
            exact[normalize_path(key)] = _password_list(values, "files[{0}]".format(key))

        defaults = _password_list(data.get("default") or [], "default")
        return cls(exact=exact, defaults=defaults)

    def candidates(self, path: str) -> List[PasswordCandidate]:
        """返回该文件的候选密码（精确优先，其次 default）。"""
        normalized = normalize_path(path)
        exact = self._exact.get(normalized, [])
        if exact:
            return [
                PasswordCandidate(password=value, source="exact", index=index)
                for index, value in enumerate(exact, start=1)
            ]
        return [
            PasswordCandidate(password=value, source="default", index=index)
            for index, value in enumerate(self._defaults, start=1)
        ]
