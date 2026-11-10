"""配置加载与校验。

启动阶段的全部检查集中在这里：配置文件可读、YAML 可解析、字段类型与必填项、
输入路径存在、新增文件来源存在、输出/日志目录可写、7z 可执行文件可定位、
输出命名后缀合法。任何问题都以 :class:`ConfigError` 抛出并携带字段名，
入口据此返回退出码 2。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Tuple

import yaml


class ConfigError(Exception):
    """配置或环境错误（入口退出码 2）。"""

    def __init__(self, field_name: str, message: str) -> None:
        super().__init__("{0}: {1}".format(field_name, message))
        self.field_name = field_name
        self.message = message


_MISSING = object()

_INVALID_NAME_CHARS = set('<>:"/\\|?*')
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}
_PASS_VIA = {"stdin", "arg"}


@dataclass
class InputConfig:
    """输入扫描配置。"""

    paths: List[str]
    recursive: bool
    extensions: List[str]


@dataclass
class PasswordConfig:
    """密码表与新密码配置。"""

    table_file: str
    new_password: str
    pass_via: str = "stdin"
    stdin_encoding: str = "auto"


@dataclass
class AddFile:
    """需要注入到解压目录的文件。"""

    source: str
    target_path: str


@dataclass
class OutputConfig:
    """输出目录与命名规则。"""

    dir: str
    keep_relative_structure: bool = True
    rename_on_conflict: str = "副本"


@dataclass
class ArchiveConfig:
    """压缩引擎配置。"""

    seven_zip_path: str = ""
    seven_zip_error: str = ""
    allow_zip_fallback: bool = False
    code_page: Optional[int] = None
    sevenz_encrypt_header: bool = True
    zip_aes: bool = True


@dataclass
class LogConfig:
    """日志配置。"""

    dir: str
    file: str = "process.log"
    level: str = "INFO"
    log_password: bool = True
    console: bool = True


@dataclass
class AppConfig:
    """完整运行配置。"""

    config_path: str
    base_dir: str
    input: InputConfig
    password: PasswordConfig
    ad_keywords: List[str]
    add_files: List[AddFile]
    output: OutputConfig
    archive: ArchiveConfig
    log: LogConfig


def _section(data: Mapping[str, Any], key: str, field_name: str) -> Mapping[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ConfigError(field_name, "缺失或不是对象")
    return value


def _text(
    mapping: Mapping[str, Any],
    key: str,
    field_name: str,
    *,
    default: Any = _MISSING,
    allow_empty: bool = False,
    strip: bool = True,
) -> str:
    value = mapping.get(key, default)
    if value is _MISSING or value is None:
        if default is _MISSING:
            raise ConfigError(field_name, "必填字段缺失")
        value = default
    if not isinstance(value, str):
        raise ConfigError(field_name, "必须是字符串")
    result = value.strip() if strip else value
    if not allow_empty and not result.strip():
        raise ConfigError(field_name, "不能为空")
    return result


def _boolean(mapping: Mapping[str, Any], key: str, field_name: str, default: bool) -> bool:
    value = mapping.get(key, default)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(field_name, "必须是 true 或 false")
    return value


def _str_list(
    mapping: Mapping[str, Any],
    key: str,
    field_name: str,
    *,
    default: Any = _MISSING,
    allow_empty: bool = False,
) -> List[str]:
    value = mapping.get(key, default)
    if value is _MISSING or value is None:
        if default is _MISSING:
            raise ConfigError(field_name, "必填字段缺失")
        value = default
    if not isinstance(value, list):
        raise ConfigError(field_name, "必须是列表")
    result: List[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ConfigError("{0}[{1}]".format(field_name, index), "必须是字符串")
        cleaned = item.strip()
        if cleaned:
            result.append(cleaned)
    if not result and not allow_empty:
        raise ConfigError(field_name, "不能为空列表")
    return result


def _resolve_path(value: str) -> str:
    expanded = os.path.expandvars(os.path.expanduser(value))
    return os.path.abspath(expanded)


def _normalize_extension(value: str, field_name: str) -> str:
    cleaned = value.strip().lower().lstrip(".")
    if not cleaned:
        raise ConfigError(field_name, "后缀不能为空")
    if "/" in cleaned or "\\" in cleaned:
        raise ConfigError(field_name, "后缀不能包含路径分隔符：{0}".format(value))
    return cleaned


def _validate_target_path(target: str, field_name: str) -> None:
    normalized = target.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise ConfigError(field_name, "必须是相对路径")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts:
        raise ConfigError(field_name, "不能为空")
    if ".." in parts:
        raise ConfigError(field_name, "不允许包含 ..")
    if any(char in _INVALID_NAME_CHARS for part in parts for char in part):
        raise ConfigError(field_name, "包含 Windows 文件名非法字符")


def _prepare_dir(path: str, field_name: str, *, create: bool) -> None:
    if os.path.exists(path):
        if not os.path.isdir(path):
            raise ConfigError(field_name, "不是目录：{0}".format(path))
        if not os.access(path, os.W_OK):
            raise ConfigError(field_name, "目录不可写：{0}".format(path))
        return
    if not create:
        parent = path
        while parent and not os.path.exists(parent):
            parent = os.path.dirname(parent)
        if not parent or not os.path.isdir(parent):
            raise ConfigError(field_name, "父目录不存在：{0}".format(path))
        return
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        raise ConfigError(field_name, "无法创建目录：{0}".format(exc)) from exc


def _resolve_seven_zip(value: str, base_dir: str) -> Tuple[str, str]:
    """定位 7z 可执行文件，返回 (绝对路径, 错误信息)。"""
    expanded = os.path.expandvars(os.path.expanduser(value))
    if os.path.isabs(expanded):
        candidates = [os.path.normpath(expanded)]
    else:
        candidates = [
            os.path.abspath(expanded),
            os.path.normpath(os.path.join(base_dir, expanded)),
        ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate, ""
    message = "7z 可执行文件不存在：{0}（已尝试：{1}）".format(value, "、".join(candidates))
    return "", message


def _build(
    data: Mapping[str, Any],
    base_dir: str,
    config_path: str,
    *,
    dry_run: bool,
) -> AppConfig:
    input_raw = _section(data, "input", "input")
    raw_paths = _str_list(input_raw, "paths", "input.paths", allow_empty=False)
    paths = [_resolve_path(item) for item in raw_paths]
    for index, original in enumerate(raw_paths):
        if not os.path.exists(paths[index]):
            raise ConfigError("input.paths", "路径不存在：{0}".format(original))
    recursive = _boolean(input_raw, "recursive", "input.recursive", True)
    extensions = [
        _normalize_extension(item, "input.extensions")
        for item in _str_list(input_raw, "extensions", "input.extensions", allow_empty=False)
    ]

    password_raw = _section(data, "password", "password")
    table_file = _resolve_path(_text(password_raw, "table_file", "password.table_file"))
    if not os.path.isfile(table_file):
        raise ConfigError("password.table_file", "文件不存在：{0}".format(table_file))
    new_password = _text(password_raw, "new_password", "password.new_password", strip=False)
    pass_via = _text(password_raw, "pass_via", "password.pass_via", default="stdin").lower()
    if pass_via not in _PASS_VIA:
        raise ConfigError("password.pass_via", "必须是 stdin 或 arg")
    stdin_encoding = _text(
        password_raw, "stdin_encoding", "password.stdin_encoding", default="auto"
    )

    ad_keywords = _str_list(
        data, "ad_keywords", "ad_keywords", default=[], allow_empty=True
    )

    add_raw = data.get("add_files") or []
    if not isinstance(add_raw, list):
        raise ConfigError("add_files", "必须是列表")
    add_files: List[AddFile] = []
    for index, item in enumerate(add_raw):
        field_name = "add_files[{0}]".format(index)
        if not isinstance(item, dict):
            raise ConfigError(field_name, "必须是对象")
        source = _resolve_path(_text(item, "source", "{0}.source".format(field_name)))
        target = _text(item, "target_path", "{0}.target_path".format(field_name))
        _validate_target_path(target, "{0}.target_path".format(field_name))
        if not os.path.isfile(source):
            raise ConfigError(
                "{0}.source".format(field_name), "文件不存在：{0}".format(source)
            )
        add_files.append(AddFile(source=source, target_path=target.replace("\\", "/")))

    output_raw = _section(data, "output", "output")
    output_dir = _resolve_path(_text(output_raw, "dir", "output.dir"))
    keep_relative = _boolean(
        output_raw, "keep_relative_structure", "output.keep_relative_structure", True
    )
    rename_word = _text(
        output_raw, "rename_on_conflict", "output.rename_on_conflict", default="副本"
    )
    if any(char in _INVALID_NAME_CHARS for char in rename_word):
        raise ConfigError("output.rename_on_conflict", "包含 Windows 文件名非法字符")

    archive_raw = _section(data, "archive", "archive")
    seven_raw = _text(archive_raw, "seven_zip_path", "archive.seven_zip_path")
    allow_fallback = _boolean(
        archive_raw, "allow_zip_fallback", "archive.allow_zip_fallback", False
    )
    code_page = archive_raw.get("code_page")
    if code_page is not None:
        if isinstance(code_page, bool) or not isinstance(code_page, int):
            raise ConfigError("archive.code_page", "必须是整数或 null")
        if not 1 <= code_page <= 65535:
            raise ConfigError("archive.code_page", "必须在 1-65535 之间")
    encrypt_header = _boolean(
        archive_raw, "sevenz_encrypt_header", "archive.sevenz_encrypt_header", True
    )
    zip_aes = _boolean(archive_raw, "zip_aes", "archive.zip_aes", True)

    log_raw = _section(data, "log", "log")
    log_dir = _resolve_path(_text(log_raw, "dir", "log.dir"))
    log_file = _text(log_raw, "file", "log.file", default="process.log")
    if "/" in log_file or "\\" in log_file:
        raise ConfigError("log.file", "只能是文件名，不能包含目录")
    level = _text(log_raw, "level", "log.level", default="INFO").upper()
    if level not in _LOG_LEVELS:
        raise ConfigError("log.level", "必须是 DEBUG/INFO/WARNING/ERROR")
    log_password = _boolean(log_raw, "log_password", "log.log_password", True)
    console = _boolean(log_raw, "console", "log.console", True)

    _prepare_dir(output_dir, "output.dir", create=not dry_run)
    _prepare_dir(log_dir, "log.dir", create=True)

    seven_path, seven_error = _resolve_seven_zip(seven_raw, base_dir)
    if not seven_path and not allow_fallback:
        raise ConfigError(
            "archive.seven_zip_path",
            "{0}；若仅处理非分卷 zip，可设置 archive.allow_zip_fallback: true 启用 pyzipper 备选".format(
                seven_error
            ),
        )

    return AppConfig(
        config_path=config_path,
        base_dir=base_dir,
        input=InputConfig(paths=paths, recursive=recursive, extensions=extensions),
        password=PasswordConfig(
            table_file=table_file,
            new_password=new_password,
            pass_via=pass_via,
            stdin_encoding=stdin_encoding,
        ),
        ad_keywords=ad_keywords,
        add_files=add_files,
        output=OutputConfig(
            dir=output_dir,
            keep_relative_structure=keep_relative,
            rename_on_conflict=rename_word,
        ),
        archive=ArchiveConfig(
            seven_zip_path=seven_path,
            seven_zip_error=seven_error,
            allow_zip_fallback=allow_fallback,
            code_page=code_page,
            sevenz_encrypt_header=encrypt_header,
            zip_aes=zip_aes,
        ),
        log=LogConfig(
            dir=log_dir,
            file=log_file,
            level=level,
            log_password=log_password,
            console=console,
        ),
    )


def load_config(config_path: str, *, dry_run: bool = False) -> AppConfig:
    """加载并校验配置；失败抛出 :class:`ConfigError`。"""
    path = _resolve_path(config_path)
    if not os.path.isfile(path):
        raise ConfigError("config", "配置文件不存在：{0}".format(config_path))
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            raw = yaml.safe_load(handle)
    except OSError as exc:
        raise ConfigError("config", "无法读取配置文件：{0}".format(exc)) from exc
    except yaml.YAMLError as exc:
        raise ConfigError("config", "YAML 解析失败：{0}".format(exc)) from exc
    if not isinstance(raw, Mapping):
        raise ConfigError("config", "根节点必须是对象")
    return _build(raw, os.path.dirname(path), path, dry_run=dry_run)
