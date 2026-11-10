"""日志。

文件日志使用 JSON Lines（每行一个 JSON 对象），便于后续统计与检索；
控制台按配置输出人类可读文本。每个文件的处理结果作为一条 ``record`` 写入，
包含任务书要求的全部字段。
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime
from typing import Any, Dict

from config_loader import LogConfig

_LEVEL_ORDER = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
_STATUS_LEVEL = {
    "SUCCESS": "INFO",
    "DRY_RUN": "INFO",
    "SKIPPED": "WARNING",
    "FAILED": "ERROR",
}


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _short_time() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


class ProcessLogger:
    """文件 + 控制台双通道日志器。"""

    def __init__(self, config: LogConfig) -> None:
        os.makedirs(config.dir, exist_ok=True)
        self.path = os.path.join(config.dir, config.file)
        self._handle = open(self.path, "a", encoding="utf-8")
        self._console = config.console
        self._threshold = _LEVEL_ORDER.get(config.level.upper(), 20)
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            try:
                self._handle.close()
            except OSError:
                pass

    def _write(self, payload: Dict[str, Any]) -> None:
        line = json.dumps(payload, ensure_ascii=False, default=str)
        with self._lock:
            self._handle.write(line + "\n")
            self._handle.flush()

    def _print(self, level: str, message: str) -> None:
        if not self._console:
            return
        stream = sys.stderr if level in ("WARNING", "ERROR") else sys.stdout
        line = "{0} [{1}] {2}".format(_short_time(), level, message)
        try:
            print(line, file=stream)
        except UnicodeEncodeError:
            encoding = getattr(stream, "encoding", None) or "utf-8"
            print(line.encode(encoding, "replace").decode(encoding, "replace"), file=stream)

    def _message(self, level: str, message: str) -> None:
        if _LEVEL_ORDER[level] < self._threshold:
            return
        self._write(
            {
                "timestamp": _now(),
                "type": "message",
                "level": level,
                "message": message,
            }
        )
        self._print(level, message)

    def debug(self, message: str) -> None:
        self._message("DEBUG", message)

    def info(self, message: str) -> None:
        self._message("INFO", message)

    def warning(self, message: str) -> None:
        self._message("WARNING", message)

    def error(self, message: str) -> None:
        self._message("ERROR", message)

    def record(self, payload: Dict[str, Any]) -> None:
        """写入一条文件处理记录（始终落盘，不受 level 限制）。"""
        body = dict(payload)
        body.setdefault("timestamp", _now())
        body["type"] = "record"
        self._write(body)

        if not self._console:
            return
        status = str(body.get("status") or "INFO")
        level = _STATUS_LEVEL.get(status, "INFO")
        line = "[{0}] {1}".format(status, body.get("source"))
        if body.get("output"):
            line += " -> {0}".format(body["output"])
        if body.get("renamed"):
            line += "（副本）"
        if status == "DRY_RUN" and body.get("old_password"):
            line += "（密码命中）"
        if body.get("error"):
            line += " | {0}".format(body["error"])
        self._print(level, line)
