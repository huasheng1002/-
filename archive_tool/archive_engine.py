"""压缩引擎封装。

主引擎 :class:`SevenZipEngine` 以子进程调用随程序分发的 ``7z.exe``，
负责解压、压缩、加密、分卷与中文文件名编码；密码默认经 stdin 传入，
失败后回退到命令行 ``-pPASSWORD``。

备选引擎 :class:`ZipFallbackEngine` 仅在 7z 不可用、且全部任务为非分卷
zip 时启用（需要安装 pyzipper）。
"""

from __future__ import annotations

import ctypes
import glob
import locale
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple


class ArchiveError(Exception):
    """压缩/解压操作失败。"""

    def __init__(self, message: str, stderr: str = "", returncode: int = -1) -> None:
        super().__init__(message)
        self.message = message
        self.stderr = stderr
        self.returncode = returncode


@dataclass
class RunResult:
    """一次 7z 进程调用的结果。"""

    returncode: int
    stdout: str
    stderr: str
    used_stdin: bool = False


# 7z 的密码相关错误特征（用于判断是否需要回退到命令行传参）
_PASSWORD_HINTS = (
    "wrong password",
    "password is incorrect",
    "can not open encrypted",
    "cannot open encrypted",
    "enter password",
    "encrypted archive",
)

# 损坏/格式不支持的错误特征（不再尝试后续密码）
_CORRUPT_HINTS = (
    "cannot open the file as archive",
    "can not open the file as archive",
    "is not archive",
    "can not open as archive",
    "unsupported method",
    "is not supported archive",
)

# 乱码字符：cp437 框线区与常见的 Latin-1 误解码标记
_MOJIBAKE_CHARS = set("ÃÂÐÑï¼ã€â€")
_MOJIBAKE_BLOCKS = ((0x2500, 0x257F),)


def _oem_encoding() -> str:
    """Windows 控制台输入代码页对应的 Python 编码名。"""
    if sys.platform == "win32":
        try:
            code_page = ctypes.windll.kernel32.GetOEMCP()
            return "cp{0}".format(code_page)
        except Exception:  # pragma: no cover - 极端环境
            return "mbcs"
    return locale.getpreferredencoding(False) or "utf-8"


def _creation_flags() -> int:
    if sys.platform == "win32":
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return 0


def _decode(data: Optional[bytes]) -> str:
    if not data:
        return ""
    return data.decode("utf-8", "replace")


def _short(text: str, limit: int = 300) -> str:
    compact = re.sub(r"\s+", " ", text or "").strip()
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "…"


def _is_success(result: RunResult) -> bool:
    """7z 退出码 0/1 视为可用，但输出里出现密码错误时仍算失败。"""
    if result.returncode not in (0, 1):
        return False
    combined = (result.stderr + "\n" + result.stdout).casefold()
    return "wrong password" not in combined


def _is_mojibake_char(char: str) -> bool:
    if char in _MOJIBAKE_CHARS:
        return True
    code = ord(char)
    return any(start <= code <= end for start, end in _MOJIBAKE_BLOCKS)


def has_mojibake(root: str) -> bool:
    """检测解压结果中是否存在典型的文件名乱码。"""
    for _current, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + list(filenames):
            if "锟斤拷" in name or "烫烫烫" in name:
                return True
            score = sum(1 for char in name if _is_mojibake_char(char))
            if score >= 2:
                return True
    return False


def _is_ascii(text: str) -> bool:
    try:
        text.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def _encode_zip_password(password: str) -> bytes:
    """zip 密码按本机 ANSI/OEM 代码页编码，与 WinRAR/7-Zip 的读取方式一致。"""
    for encoding in (_oem_encoding(), "utf-8"):
        try:
            return password.encode(encoding)
        except (UnicodeEncodeError, LookupError):
            continue
    return password.encode("utf-8", "replace")


def _write_tree(zip_handle: Any, root: str) -> None:
    """把目录树写入 zip；空目录以 ``dir/`` 条目保留。"""
    for current, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        relative = os.path.relpath(current, root)
        if relative == ".":
            relative = ""
        if not dirnames and not filenames and relative:
            zip_handle.writestr(relative.replace(os.sep, "/") + "/", b"")
        for name in filenames:
            full = os.path.join(current, name)
            arcname = os.path.join(relative, name).replace(os.sep, "/")
            zip_handle.write(full, arcname)


def write_zip_aes(dest: str, password: str, root: str) -> None:
    """用 pyzipper 写 AES-256 zip。

    7-Zip 无法用非 ASCII 密码创建 zip（会报“参数错误”），此函数是该场景的
    兜底实现；密码按 OEM 代码页编码，生成的包可被 7-Zip / WinRAR 正常打开。
    """
    try:
        import pyzipper  # type: ignore
    except ImportError as exc:
        raise ArchiveError(
            "zip 格式无法使用非 ASCII 新密码创建（7-Zip 限制），且未安装 pyzipper；"
            "请安装 pyzipper，或把新密码改为 ASCII，或改用 7z 输出格式"
        ) from exc
    try:
        with pyzipper.AESZipFile(
            dest, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as handle:
            handle.setpassword(_encode_zip_password(password))
            handle.setencryption(pyzipper.WZ_AES, nbits=256)
            _write_tree(handle, root)
    except OSError as exc:
        raise ArchiveError("zip 压缩失败：{0}".format(exc)) from exc


def _clear_dir(path: str) -> None:
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
        return
    for entry in os.scandir(path):
        try:
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.path, ignore_errors=True)
            else:
                os.remove(entry.path)
        except OSError:
            continue


class SevenZipEngine:
    """7z 命令行引擎。"""

    def __init__(
        self,
        exe_path: str,
        *,
        code_page: Optional[int] = None,
        pass_via: str = "stdin",
        stdin_encoding: str = "auto",
    ) -> None:
        self.exe = os.path.abspath(exe_path)
        self.code_page = code_page
        self.pass_via = pass_via if pass_via in ("stdin", "arg") else "stdin"
        self.stdin_encoding = stdin_encoding or "auto"
        # 运行时探测：Windows 版 7-Zip 无法从管道读取密码，探测到后直接走 -p 参数
        self._stdin_ok: Optional[bool] = None
        self.stdin_fallback_used = False

    # ------------------------------------------------------------------ 基础
    def probe(self) -> None:
        """校验 7z 可执行文件存在且可运行。"""
        if not os.path.isfile(self.exe):
            raise ArchiveError("7z 可执行文件不存在：{0}".format(self.exe))
        try:
            completed = subprocess.run(
                [self.exe, "i"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                creationflags=_creation_flags(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ArchiveError("7z 可执行文件无法运行：{0}".format(exc)) from exc
        if completed.returncode != 0:
            raise ArchiveError("7z 自检失败（退出码 {0}）".format(completed.returncode))

    def _encode_password(self, password: str) -> bytes:
        encodings: List[str] = []
        if self.stdin_encoding.lower() not in ("auto", ""):
            encodings.append(self.stdin_encoding)
        else:
            encodings.extend([_oem_encoding(), "utf-8"])
        for encoding in encodings:
            try:
                return password.encode(encoding)
            except (UnicodeEncodeError, LookupError):
                continue
        return password.encode("utf-8", "replace")

    def _run(
        self,
        args: Sequence[str],
        password: Optional[str] = None,
        *,
        use_stdin: bool = False,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        prompt_lines: int = 2,
    ) -> RunResult:
        command = [self.exe, args[0], "-bd", "-sccUTF-8"]
        payload: Optional[bytes] = None
        if password is not None:
            if use_stdin:
                command.append("-p")
                line = self._encode_password(password) + b"\n"
                payload = line * max(1, prompt_lines)
            else:
                command.append("-p{0}".format(password))
        command.extend(args[1:])

        kwargs = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": cwd,
            "timeout": timeout,
            "creationflags": _creation_flags(),
        }
        try:
            if payload is not None:
                completed = subprocess.run(command, input=payload, **kwargs)
            else:
                completed = subprocess.run(command, stdin=subprocess.DEVNULL, **kwargs)
        except subprocess.TimeoutExpired as exc:
            raise ArchiveError("7z 执行超时：{0}".format(timeout)) from exc
        except OSError as exc:
            raise ArchiveError("7z 执行失败：{0}".format(exc)) from exc

        return RunResult(
            returncode=completed.returncode,
            stdout=_decode(completed.stdout),
            stderr=_decode(completed.stderr),
            used_stdin=use_stdin,
        )

    @staticmethod
    def _looks_like_password_failure(result: RunResult) -> bool:
        combined = (result.stderr + "\n" + result.stdout).casefold()
        return any(hint in combined for hint in _PASSWORD_HINTS)

    @staticmethod
    def _failure_message(prefix: str, result: RunResult) -> str:
        detail = _short(result.stderr or result.stdout)
        if detail:
            return "{0}（退出码 {1}）：{2}".format(prefix, result.returncode, detail)
        return "{0}（退出码 {1}）".format(prefix, result.returncode)

    def _run_with_password(
        self,
        args: Sequence[str],
        password: str,
        *,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        before_retry: Optional[Any] = None,
        retry_on_any_failure: bool = False,
    ) -> RunResult:
        """优先 stdin 传密码，失败时回退 ``-pPASSWORD``。

        一旦确认某次回退成功（说明 stdin 不可用），后续调用直接使用参数方式，
        避免每个文件都做一次无谓的失败尝试。
        """
        use_stdin = self.pass_via == "stdin" and self._stdin_ok is not False
        result = self._run(args, password, use_stdin=use_stdin, cwd=cwd, timeout=timeout)
        if _is_success(result):
            if use_stdin:
                self._stdin_ok = True
            return result

        should_retry = use_stdin and (
            retry_on_any_failure or self._looks_like_password_failure(result)
        )
        if not should_retry:
            return result

        if before_retry is not None:
            before_retry()
        retry = self._run(args, password, use_stdin=False, cwd=cwd, timeout=timeout)
        if _is_success(retry):
            self._stdin_ok = False
            self.stdin_fallback_used = True
        return retry

    # ------------------------------------------------------------------ 解压
    def _extract_once(
        self,
        archive: str,
        dest: str,
        password: str,
        *,
        force_code_page: Optional[int] = None,
    ) -> None:
        args = ["x", "-y", "-bb0"]
        code_page = force_code_page or self.code_page
        if code_page:
            args.append("-mcp={0}".format(code_page))
        args.extend(["-o{0}".format(dest), archive])
        result = self._run_with_password(args, password)
        if not _is_success(result):
            raise ArchiveError(
                self._failure_message("解压失败", result), result.stderr, result.returncode
            )

    def extract(self, archive: str, dest: str, password: str, kind: str = "zip") -> None:
        """解压到 ``dest``；zip 出现文件名乱码时用 ``-mcp=936`` 重试。"""
        os.makedirs(dest, exist_ok=True)
        self._extract_once(archive, dest, password)
        if kind == "zip" and not self.code_page and has_mojibake(dest):
            _clear_dir(dest)
            try:
                self._extract_once(archive, dest, password, force_code_page=936)
            except ArchiveError as exc:
                raise ArchiveError(
                    "中文文件名重试失败：{0}".format(exc.message), exc.stderr, exc.returncode
                ) from exc

    def test_archive(
        self, archive: str, password: str, timeout: Optional[float] = None
    ) -> Tuple[bool, str, int]:
        """干跑用：仅测试压缩包可解，不落盘。"""
        result = self._run_with_password(["t", archive], password, timeout=timeout)
        return _is_success(result), result.stderr, result.returncode

    # ------------------------------------------------------------------ 压缩
    def _remove_outputs(self, dest_base: str) -> None:
        for path in [dest_base] + glob.glob(dest_base + ".[0-9][0-9][0-9]"):
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                continue

    def compress(
        self,
        dest_base: str,
        kind: str,
        password: str,
        temp_dir: str,
        *,
        encrypt_header: bool = True,
        aes: bool = True,
        volume_size: Optional[int] = None,
    ) -> None:
        """把 ``temp_dir`` 的内容重新压缩加密到 ``dest_base``。

        分卷输出时 ``dest_base`` 不带 ``.001``，由 7z 生成 ``.001`` 起的卷。
        """
        if kind == "zip" and not _is_ascii(password):
            # 7-Zip 无法用非 ASCII 密码创建 zip，交给 pyzipper 兜底（密码按 OEM 编码）
            if volume_size:
                raise ArchiveError(
                    "zip 分卷输出无法使用非 ASCII 新密码（7-Zip 限制）；"
                    "请改用 ASCII 新密码或改为单卷输出"
                )
            write_zip_aes(dest_base, password, temp_dir)
            return

        args = ["a", "-y", "-bb0"]
        if kind == "7z":
            args.extend(["-t7z", "-mx=5"])
            if encrypt_header:
                args.append("-mhe=on")
        elif kind == "zip":
            args.append("-tzip")
            if aes:
                args.append("-mem=AES256")
        else:
            raise ArchiveError("不支持的输出格式：{0}".format(kind))
        if volume_size:
            args.append("-v{0}b".format(volume_size))
        args.extend([dest_base, "*"])

        result = self._run_with_password(
            args,
            password,
            cwd=temp_dir,
            before_retry=lambda: self._remove_outputs(dest_base),
            retry_on_any_failure=True,
        )
        if not _is_success(result):
            raise ArchiveError(
                self._failure_message("压缩失败", result), result.stderr, result.returncode
            )

    # ------------------------------------------------------------------ 校验
    def list_ok(self, entry: str, password: str, timeout: Optional[float] = None) -> bool:
        result = self._run_with_password(["l", entry], password, timeout=timeout)
        return _is_success(result)

    def is_encrypted(self, entry: str, kind: str = "zip", timeout: float = 3600) -> bool:
        """无密码测试：需要密码或密码错误即说明已加密。"""
        if not os.path.isfile(entry):
            return False
        result = self._run(["t", entry], None, timeout=timeout)
        combined = (result.stderr + "\n" + result.stdout).casefold()
        if "wrong password" in combined or "enter password" in combined:
            return True
        return result.returncode not in (0, 1)

    @staticmethod
    def is_corrupt_error(stderr: str) -> bool:
        combined = (stderr or "").casefold()
        if "wrong password" in combined:
            return False
        return any(hint in combined for hint in _CORRUPT_HINTS)


class Py7zrFallbackEngine:
    """py7zr 兜底引擎占位。

    按技术选型保留代码入口，默认禁用、不进入生产路径：py7zr 在多卷场景存在
    内存膨胀与 CRC 失败风险，因此 :func:`main._select_engine` 不会实例化本类。
    如需实验性启用，请自行接入并充分测试。
    """

    ENABLED = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise ArchiveError("py7zr 兜底引擎已禁用，不进入生产路径")


class ZipFallbackEngine:
    """pyzipper 备选引擎（仅非分卷 zip，7z 不可用时手动启用）。"""

    def __init__(self, *, stdin_encoding: str = "auto") -> None:
        try:
            import pyzipper  # type: ignore
        except ImportError as exc:  # pragma: no cover - 依赖缺失
            raise ArchiveError("pyzipper 未安装，无法启用备选引擎（pip install pyzipper）") from exc
        self._pyzipper = pyzipper
        self.stdin_encoding = stdin_encoding or "auto"

    def probe(self) -> None:
        return None

    def _password_encodings(self) -> List[str]:
        encodings = [_oem_encoding(), "utf-8"]
        unique: List[str] = []
        for item in encodings:
            if item not in unique:
                unique.append(item)
        return unique

    def extract(self, archive: str, dest: str, password: str, kind: str = "zip") -> None:
        if kind != "zip":
            raise ArchiveError("pyzipper 备选引擎仅支持 zip")
        os.makedirs(dest, exist_ok=True)
        errors: List[str] = []
        for encoding in self._password_encodings():
            try:
                with self._pyzipper.AESZipFile(archive) as handle:
                    handle.pwd = password.encode(encoding)
                    handle.extractall(dest)
                return
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
                errors.append("{0}: {1}".format(encoding, exc))
        raise ArchiveError("解压失败：{0}".format("；".join(errors)))

    def test_archive(
        self, archive: str, password: str, timeout: Optional[float] = None
    ) -> Tuple[bool, str, int]:
        last_error = ""
        for encoding in self._password_encodings():
            try:
                with self._pyzipper.AESZipFile(archive) as handle:
                    handle.pwd = password.encode(encoding)
                    names = [item for item in handle.namelist() if not item.endswith("/")]
                    if not names:
                        return True, "", 0
                    handle.read(names[0])
                return True, "", 0
            except (RuntimeError, zipfile.BadZipFile) as exc:
                last_error = str(exc)
        return False, last_error, 2

    def compress(
        self,
        dest_base: str,
        kind: str,
        password: str,
        temp_dir: str,
        *,
        encrypt_header: bool = True,
        aes: bool = True,
        volume_size: Optional[int] = None,
    ) -> None:
        if kind != "zip":
            raise ArchiveError("pyzipper 备选引擎仅支持 zip")
        if volume_size:
            raise ArchiveError("pyzipper 备选引擎不支持分卷输出")
        pyzipper = self._pyzipper
        try:
            with pyzipper.AESZipFile(
                dest_base,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as handle:
                handle.setpassword(_encode_zip_password(password))
                handle.setencryption(pyzipper.WZ_AES, nbits=256)
                _write_tree(handle, temp_dir)
        except OSError as exc:
            raise ArchiveError("压缩失败：{0}".format(exc)) from exc

    def list_ok(self, entry: str, password: str, timeout: Optional[float] = None) -> bool:
        try:
            with self._pyzipper.AESZipFile(entry) as handle:
                handle.namelist()
            return True
        except (OSError, zipfile.BadZipFile):
            return False

    def is_encrypted(self, entry: str, kind: str = "zip", timeout: float = 3600) -> bool:
        try:
            with self._pyzipper.AESZipFile(entry) as handle:
                return any(info.flag_bits & 0x1 for info in handle.infolist())
        except (OSError, zipfile.BadZipFile):
            return False

    @staticmethod
    def is_corrupt_error(stderr: str) -> bool:
        combined = (stderr or "").casefold()
        return "badzipfile" in combined or "not a zip file" in combined
