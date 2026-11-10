"""加密压缩包批量处理工具：命令行入口与流水线编排。

流水线（每个文件独立执行，单文件失败不影响其他文件）：

1. 解析密码候选，按优先级尝试解压，命中后记录密码与来源；
2. 递归删除文件名含广告关键词的文件（保留空目录）；
3. 覆盖式注入配置指定的新增文件；
4. 计算不冲突的输出路径（重名加“副本”）；
5. 用统一新密码重新压缩加密；
6. 校验输出可列出且确实加密；
7. 写日志，清理临时目录。
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Sequence

from archive_engine import ArchiveError, SevenZipEngine, ZipFallbackEngine
from cleaner import clean_ad_files
from config_loader import AppConfig, ConfigError, load_config
from injector import inject_files
from logger import ProcessLogger
from output_namer import plan_output
from password_resolver import PasswordCandidate, PasswordResolver, PasswordTableError
from scanner import ArchiveTask, scan_inputs, task_for_path


@dataclass
class Stats:
    """运行统计。"""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    matched: int = 0
    started: float = 0.0


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _short(text: str, limit: int = 300) -> str:
    compact = " ".join((text or "").split())
    return compact if len(compact) <= limit else compact[:limit] + "…"


def _visible(value: Optional[str], enabled: bool) -> Optional[str]:
    if value is None:
        return None
    return value if enabled else "******"


def _append_warnings(record: Dict[str, Any], messages: Sequence[str]) -> None:
    if messages:
        record.setdefault("warnings", []).extend(str(item) for item in messages)


def _finish(record: Dict[str, Any], started: float) -> Dict[str, Any]:
    record["duration_ms"] = int((time.monotonic() - started) * 1000)
    return record


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="archive-tool",
        description="批量解压、清理、注入并重新加密 zip/7z 压缩包。",
    )
    parser.add_argument("--config", required=True, metavar="FILE", help="配置文件路径（YAML）")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只扫描并匹配密码，不写出任何文件",
    )
    parser.add_argument("--only", metavar="PATH", help="只处理指定的一个压缩包")
    return parser


# ---------------------------------------------------------------------- 引擎
def _select_engine(
    config: AppConfig, tasks: Sequence[ArchiveTask], logger: ProcessLogger
) -> Any:
    """选择 7z 主引擎或 pyzipper 备选引擎。"""
    archive_config = config.archive
    if archive_config.seven_zip_path:
        engine = SevenZipEngine(
            archive_config.seven_zip_path,
            code_page=archive_config.code_page,
            pass_via=config.password.pass_via,
            stdin_encoding=config.password.stdin_encoding,
        )
        try:
            engine.probe()
            return engine
        except ArchiveError as exc:
            logger.warning(str(exc))
    else:
        logger.warning(archive_config.seven_zip_error or "未配置 7z.exe")

    if not archive_config.allow_zip_fallback:
        logger.error(
            "7z 不可用。若仅处理非分卷 zip，可设置 archive.allow_zip_fallback: true "
            "并安装 pyzipper 后重试"
        )
        return None
    if any(task.kind != "zip" or task.is_volume for task in tasks):
        logger.error("存在 7z 或分卷压缩包，必须提供可用的 7z.exe")
        return None
    try:
        fallback = ZipFallbackEngine(stdin_encoding=config.password.stdin_encoding)
    except ArchiveError as exc:
        logger.error(str(exc))
        return None
    logger.warning("已启用 pyzipper 备选引擎（仅非分卷 zip，不支持分卷/7z/-mhe）")
    return fallback


# ---------------------------------------------------------------------- 流水线
def _create_temp_dir() -> str:
    base = os.path.join(tempfile.gettempdir(), "archive_tool")
    os.makedirs(base, exist_ok=True)
    path = os.path.join(base, uuid.uuid4().hex)
    os.makedirs(path, exist_ok=True)
    return path


def _reset_dir(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path, exist_ok=True)


def _cleanup_temp(path: str, record: Dict[str, Any]) -> None:
    if not path:
        return
    try:
        shutil.rmtree(path)
    except OSError as exc:
        _append_warnings(record, ["临时目录清理失败：{0}".format(exc)])


def _find_password(
    task: ArchiveTask,
    candidates: Sequence[PasswordCandidate],
    engine: Any,
    temp_dir: str,
) -> "tuple[Optional[PasswordCandidate], bool, str]":
    """按优先级尝试解压，返回 (命中密码, 是否损坏, 最后错误摘要)。"""
    last_detail = ""
    for candidate in candidates:
        _reset_dir(temp_dir)
        try:
            engine.extract(task.path, temp_dir, candidate.password, task.kind)
            return candidate, False, ""
        except ArchiveError as exc:
            last_detail = _short(exc.stderr or str(exc))
            if engine.is_corrupt_error(exc.stderr) or "中文文件名重试失败" in exc.message:
                return None, True, last_detail
    return None, False, last_detail


def _run_dry_run(
    task: ArchiveTask,
    candidates: Sequence[PasswordCandidate],
    record: Dict[str, Any],
    engine: Any,
    config: AppConfig,
) -> None:
    last_detail = ""
    for candidate in candidates:
        ok, stderr, _code = engine.test_archive(task.path, candidate.password)
        if ok:
            record["old_password"] = _visible(candidate.password, config.log.log_password)
            record["password_source"] = candidate.source
            record["password_index"] = candidate.index
            record["status"] = "DRY_RUN"
            return
        last_detail = _short(stderr)
        if engine.is_corrupt_error(stderr):
            record["status"] = "FAILED"
            record["error"] = "无法解压：{0}".format(last_detail)
            return
    record["status"] = "SKIPPED"
    record["error"] = "密码未命中（已尝试 {0} 个候选）".format(len(candidates))
    if last_detail:
        record["error"] += "；最后错误：{0}".format(last_detail)


def _relative_output_path(task: ArchiveTask, config: AppConfig) -> str:
    if not config.output.keep_relative_structure:
        return os.path.basename(task.path)
    relative = os.path.relpath(task.path, task.root)
    if relative.startswith(".."):
        return os.path.basename(task.path)
    return relative


def _volume_size(task: ArchiveTask, record: Dict[str, Any]) -> Optional[int]:
    try:
        size = os.path.getsize(task.path)
    except OSError as exc:
        _append_warnings(record, ["无法读取源分卷大小：{0}".format(exc)])
        return None
    if size <= 0:
        _append_warnings(record, ["源分卷大小为 0，按单卷输出"])
        return None
    return size


def _execute(
    task: ArchiveTask,
    candidates: Sequence[PasswordCandidate],
    record: Dict[str, Any],
    config: AppConfig,
    engine: Any,
) -> None:
    temp_dir = _create_temp_dir()
    try:
        hit, fatal, detail = _find_password(task, candidates, engine, temp_dir)
        if hit is None:
            if fatal:
                record["status"] = "FAILED"
                record["error"] = "无法解压：{0}".format(detail)
            else:
                record["status"] = "SKIPPED"
                record["error"] = "密码未命中（已尝试 {0} 个候选）".format(len(candidates))
                if detail:
                    record["error"] += "；最后错误：{0}".format(detail)
            return

        record["old_password"] = _visible(hit.password, config.log.log_password)
        record["password_source"] = hit.source
        record["password_index"] = hit.index

        clean_result = clean_ad_files(temp_dir, config.ad_keywords)
        record["removed_files"] = clean_result.removed
        _append_warnings(record, clean_result.warnings)

        inject_result = inject_files(temp_dir, config.add_files)
        record["added_files"] = inject_result.added
        _append_warnings(record, inject_result.errors)

        relative = _relative_output_path(task, config)
        plan = plan_output(
            config.output.dir,
            relative,
            is_volume=task.is_volume,
            rename_word=config.output.rename_on_conflict,
        )
        os.makedirs(os.path.dirname(plan.archive_path), exist_ok=True)

        engine.compress(
            plan.archive_path,
            task.kind,
            config.password.new_password,
            temp_dir,
            encrypt_header=config.archive.sevenz_encrypt_header,
            aes=config.archive.zip_aes,
            volume_size=_volume_size(task, record) if task.is_volume else None,
        )

        if not os.path.isfile(plan.entry_path):
            raise ArchiveError("输出文件不存在：{0}".format(plan.entry_path))
        if not engine.list_ok(plan.entry_path, config.password.new_password):
            raise ArchiveError("输出校验失败：7z 无法列出 {0}".format(plan.entry_path))
        if not engine.is_encrypted(plan.entry_path, task.kind):
            raise ArchiveError("输出校验失败：未检测到加密，新密码可能未生效")

        record["output"] = plan.entry_path
        record["renamed"] = plan.renamed
        if inject_result.errors:
            record["status"] = "FAILED"
            record["error"] = "部分新增文件注入失败：{0}".format(
                "；".join(inject_result.errors)
            )
        else:
            record["status"] = "SUCCESS"
    finally:
        _cleanup_temp(temp_dir, record)


def process_task(
    task: ArchiveTask,
    config: AppConfig,
    engine: Any,
    resolver: PasswordResolver,
    dry_run: bool,
) -> Dict[str, Any]:
    """处理单个压缩包并返回日志记录。"""
    started = time.monotonic()
    record: Dict[str, Any] = {
        "timestamp": _now(),
        "source": task.path,
        "output": None,
        "status": "FAILED",
        "old_password": None,
        "password_source": None,
        "password_index": None,
        "new_password": _visible(config.password.new_password, config.log.log_password),
        "removed_files": [],
        "added_files": [],
        "renamed": False,
        "duration_ms": 0,
        "error": None,
        "candidates": 0,
        "kind": task.kind,
        "volume": task.is_volume,
    }
    if dry_run:
        record["dry_run"] = True

    try:
        if task.unsupported:
            record["status"] = "SKIPPED"
            record["error"] = task.unsupported
            return _finish(record, started)

        candidates = resolver.candidates(task.path)
        record["candidates"] = len(candidates)
        if not candidates:
            record["status"] = "SKIPPED"
            record["error"] = "密码表未提供候选密码"
            return _finish(record, started)

        if dry_run:
            _run_dry_run(task, candidates, record, engine, config)
        else:
            _execute(task, candidates, record, config, engine)
    except ArchiveError as exc:
        record["status"] = "FAILED"
        record["error"] = _short(str(exc))
    except OSError as exc:
        record["status"] = "FAILED"
        record["error"] = "系统错误：{0}".format(exc)
    except Exception as exc:  # noqa: BLE001 - 单文件失败隔离
        record["status"] = "FAILED"
        record["error"] = "{0}: {1}".format(type(exc).__name__, exc)

    return _finish(record, started)


def _update_stats(stats: Stats, record: Dict[str, Any]) -> None:
    status = record.get("status")
    if status == "SUCCESS":
        stats.succeeded += 1
    elif status == "FAILED":
        stats.failed += 1
    elif status == "SKIPPED":
        stats.skipped += 1
    elif status == "DRY_RUN":
        stats.matched += 1


def _log_summary(stats: Stats, config: AppConfig, logger: ProcessLogger, dry_run: bool) -> None:
    elapsed = time.monotonic() - stats.started
    log_path = os.path.join(config.log.dir, config.log.file)
    if dry_run:
        logger.info(
            "干跑完成：共 {0} 个，密码命中 {1}，失败 {2}，跳过 {3}，耗时 {4:.2f}s；日志：{5}".format(
                stats.total,
                stats.matched,
                stats.failed,
                stats.skipped,
                elapsed,
                log_path,
            )
        )
        return
    logger.info(
        "处理完成：共 {0} 个，成功 {1}，失败 {2}，跳过 {3}，耗时 {4:.2f}s；日志：{5}".format(
            stats.total,
            stats.succeeded,
            stats.failed,
            stats.skipped,
            elapsed,
            log_path,
        )
    )


# ---------------------------------------------------------------------- 入口
def _run(config: AppConfig, args: argparse.Namespace, logger: ProcessLogger) -> int:
    try:
        resolver = PasswordResolver.from_file(config.password.table_file)
    except PasswordTableError as exc:
        print("[配置错误] password.table_file: {0}".format(exc), file=sys.stderr)
        return 2

    temp_base = os.path.join(tempfile.gettempdir(), "archive_tool")
    os.makedirs(temp_base, exist_ok=True)

    tasks = scan_inputs(
        config.input.paths,
        recursive=config.input.recursive,
        extensions=config.input.extensions,
        skip_dirs=[config.output.dir, temp_base],
    )

    if args.only:
        target = os.path.normcase(os.path.abspath(os.path.expanduser(args.only)))
        selected = [
            task for task in tasks if os.path.normcase(os.path.abspath(task.path)) == target
        ]
        if not selected:
            if os.path.isfile(args.only):
                selected = [task_for_path(args.only)]
            else:
                logger.error("--only 指定的文件不存在：{0}".format(args.only))
                return 2
        tasks = selected

    logger.info("扫描完成：共 {0} 个待处理压缩包".format(len(tasks)))
    if not tasks:
        logger.info("没有匹配的输入文件")
        return 0

    engine = _select_engine(config, tasks, logger)
    if engine is None:
        return 2

    stats = Stats(total=len(tasks), started=time.monotonic())
    warned_stdin = False
    for task in tasks:
        record = process_task(task, config, engine, resolver, args.dry_run)
        logger.record(record)
        _update_stats(stats, record)
        if not warned_stdin and getattr(engine, "stdin_fallback_used", False):
            logger.warning(
                "当前 7z 无法从 stdin 读取密码，已回退到 -p<password> 命令行传参；"
                "密码会短暂出现在本机进程命令行中，建议在受控环境运行"
            )
            warned_stdin = True

    _log_summary(stats, config, logger, args.dry_run)
    return 1 if (stats.failed or stats.skipped) else 0


def _configure_console() -> None:
    """控制台编码不支持某些字符时用替换符输出，避免打印日志时崩溃。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            continue


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_console()
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config, dry_run=args.dry_run)
    except ConfigError as exc:
        print("[配置错误] {0}: {1}".format(exc.field_name, exc.message), file=sys.stderr)
        return 2

    try:
        logger = ProcessLogger(config.log)
    except OSError as exc:
        print("[配置错误] log.dir: 无法写入日志：{0}".format(exc), file=sys.stderr)
        return 2

    try:
        return _run(config, args, logger)
    except KeyboardInterrupt:
        logger.warning("用户中断")
        return 1
    finally:
        logger.close()


if __name__ == "__main__":
    raise SystemExit(main())
