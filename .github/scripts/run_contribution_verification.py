#!/usr/bin/env python3
"""Run the bounded, fork-only contribution test set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Sequence

import tomllib

GB = 1_000_000_000
MAX_TASK_BYTES = 12 * GB
MIN_FREE_BYTES = 4 * GB
POLL_INTERVAL_SECONDS = 1.0
PROCESS_TIMEOUT_SECONDS = 55 * 60
EVIDENCE_TAIL_BYTES = 64 * 1024
RUST_VERSION = "1.99.1"
PROCESS_TERMINATION_GRACE_SECONDS = 10.0
PROCESS_TERMINATION_FORCE_TIMEOUT_SECONDS = 15.0
WINDOWS_CREATE_SUSPENDED = 0x00000004
WINDOWS_TH32CS_SNAPTHREAD = 0x00000004
WINDOWS_THREAD_SUSPEND_RESUME = 0x0002
WINDOWS_ERROR_NO_MORE_FILES = 18
MANAGED_CARGO_ENV = {
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_DEV_DEBUG": "0",
    "CARGO_PROFILE_DEV_INCREMENTAL": "false",
    "CARGO_PROFILE_TEST_DEBUG": "0",
    "CARGO_PROFILE_TEST_INCREMENTAL": "false",
}


class VerificationError(RuntimeError):
    pass


class ResourceLimitError(VerificationError):
    def __init__(self, message: str, *, result: CommandResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class TestCommand:
    name: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class TestSummary:
    status: str
    passed: int
    failed: int
    ignored: int
    measured: int
    filtered_out: int

    @property
    def executed(self) -> int:
        return self.passed + self.failed + self.measured


@dataclass
class CommandResult:
    name: str
    command: list[str]
    return_code: int | None
    duration_seconds: float
    log_path: str
    log_bytes: int
    log_sha256: str | None
    summary: TestSummary | None
    error: str | None = None


RESULT_LINE = re.compile(
    r"^test result: (?P<status>ok|FAILED)\.\s+"
    r"(?P<passed>\d+) passed;\s+"
    r"(?P<failed>\d+) failed;\s+"
    r"(?P<ignored>\d+) ignored;\s+"
    r"(?P<measured>\d+) measured;\s+"
    r"(?P<filtered>\d+) filtered out;"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return path != parent


def validate_task_root(
    task_root: str | os.PathLike[str],
    runner_temp: str | os.PathLike[str],
    *,
    platform_name: str | None = None,
) -> None:
    platform_name = platform_name or sys.platform
    root_text = os.fspath(task_root)
    temp_text = os.fspath(runner_temp)
    if "\n" in root_text or "\r" in root_text or "\n" in temp_text or "\r" in temp_text:
        raise VerificationError("task paths must not contain newlines")

    if platform_name == "win32":
        root = PureWindowsPath(root_text)
        temp = PureWindowsPath(temp_text)
        if not root.is_absolute() or not temp.is_absolute():
            raise VerificationError("Windows task paths must be absolute")
        if root.drive.casefold() != "d:" or temp.drive.casefold() != "d:":
            raise VerificationError(
                "Windows task root, Rust, Cargo, and temp must stay on D:"
            )
        if root == temp:
            raise VerificationError("task root must be a child of RUNNER_TEMP")
        try:
            root.relative_to(temp)
        except ValueError as exc:
            raise VerificationError("task root must be inside RUNNER_TEMP") from exc
        if sys.platform == "win32":
            resolved_root = Path(root_text).resolve()
            resolved_temp = Path(temp_text).resolve()
            if not _is_within(resolved_root, resolved_temp):
                raise VerificationError("resolved task root escaped RUNNER_TEMP")
            if PureWindowsPath(str(resolved_root)).drive.casefold() != "d:":
                raise VerificationError("resolved Windows task root must stay on D:")
        return

    if platform_name != "darwin":
        raise VerificationError(f"unsupported runner platform: {platform_name}")
    root = Path(root_text).resolve()
    temp = Path(temp_text).resolve()
    if not root.is_absolute() or not temp.is_absolute() or not _is_within(root, temp):
        raise VerificationError("macOS task root must be a child of RUNNER_TEMP")


def measure_tree_bytes(root: Path) -> int:
    """Count logical bytes without following symlinks or Windows reparse points."""
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except FileNotFoundError:
            continue
        with entries:
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                total += info.st_size
                if getattr(info, "st_file_attributes", 0) & 0x400:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
    return total


def check_budgets(
    task_root: Path,
    *,
    max_task_bytes: int = MAX_TASK_BYTES,
    min_free_bytes: int = MIN_FREE_BYTES,
    disk_usage: Callable[[str | os.PathLike[str]], Any] = shutil.disk_usage,
) -> tuple[int, int]:
    used = measure_tree_bytes(task_root)
    free = disk_usage(task_root).free
    if used > max_task_bytes:
        raise ResourceLimitError(
            f"task storage exceeded {max_task_bytes} bytes ({used} bytes used)"
        )
    if free < min_free_bytes:
        raise ResourceLimitError(
            f"free-space reserve breached: {free} bytes free, {min_free_bytes} required"
        )
    return used, free


def _cargo_test(package: str, filter_name: str | None = None) -> tuple[str, ...]:
    argv = [
        "cargo",
        "test",
        "--locked",
        "--jobs",
        "2",
        "--package",
        package,
        "--lib",
    ]
    if filter_name:
        argv.append(filter_name)
    argv.extend(["--", "--test-threads=1"])
    return tuple(argv)


def build_test_commands(platform_name: str) -> list[TestCommand]:
    if platform_name not in {"win32", "darwin"}:
        raise VerificationError(f"unsupported runner platform: {platform_name}")
    commands = [
        TestCommand("model-provider", _cargo_test("codex-model-provider")),
        TestCommand("core-exec-policy", _cargo_test("codex-core", "exec_policy")),
    ]
    if platform_name == "darwin":
        commands.append(
            TestCommand(
                "app-server-daemon-selection",
                _cargo_test(
                    "codex-app-server-daemon",
                    "explicit_selection_requires_unchanged_cli_and_pins_all_versions",
                ),
            )
        )
        commands.append(
            TestCommand(
                "hooks-command-runner-process-group",
                _cargo_test(
                    "codex-hooks",
                    "cancelled_and_timed_out_hooks_kill_their_process_group",
                ),
            )
        )
    commands.extend(
        [
            TestCommand(
                "tui-legacy-resume-history",
                _cargo_test(
                    "codex-tui",
                    "cached_legacy_resume_revalidates_history_across_migration_settings",
                ),
            ),
            TestCommand(
                "tui-startup-defaults",
                _cargo_test("codex-tui", "startup_defaults_tests"),
            ),
        ]
    )
    return commands


def select_test_commands(
    platform_name: str,
    requested_tests: Sequence[str] | None = None,
) -> list[TestCommand]:
    commands = build_test_commands(platform_name)
    if requested_tests is None:
        return commands

    requested_names = list(requested_tests)
    if not requested_names:
        raise VerificationError("test selection must include at least one name")

    seen: set[str] = set()
    duplicates: list[str] = []
    for name in requested_names:
        if name in seen:
            duplicates.append(name)
        else:
            seen.add(name)
    duplicates = list(dict.fromkeys(duplicates))
    if duplicates:
        raise VerificationError(f"duplicate test name(s): {', '.join(duplicates)}")

    command_names = {command.name for command in commands}
    unknown_names = list(
        dict.fromkeys(name for name in requested_names if name not in command_names)
    )
    if unknown_names:
        raise VerificationError(f"unknown test name(s): {', '.join(unknown_names)}")

    selected_names = set(requested_names)
    return [command for command in commands if command.name in selected_names]


def parse_test_summary(log_path: Path) -> TestSummary | None:
    found: TestSummary | None = None
    with log_path.open("r", encoding="utf-8", errors="replace") as log:
        for line in log:
            match = RESULT_LINE.match(line.strip())
            if match:
                values = match.groupdict()
                found = TestSummary(
                    status=values["status"],
                    passed=int(values["passed"]),
                    failed=int(values["failed"]),
                    ignored=int(values["ignored"]),
                    measured=int(values["measured"]),
                    filtered_out=int(values["filtered"]),
                )
    return found


def validate_test_result(result: CommandResult) -> None:
    summary = result.summary
    if summary is None:
        raise VerificationError(f"{result.name}: missing Rust test-result summary")
    if summary.executed == 0:
        raise VerificationError(f"{result.name}: no tests executed")
    if result.return_code != 0 or summary.status != "ok" or summary.failed:
        raise VerificationError(
            f"{result.name}: test command failed with exit {result.return_code}"
        )


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    length = 0
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            length += len(chunk)
            digest.update(chunk)
    return length, digest.hexdigest()


def _write_bounded_tail(log_path: Path, destination: Path) -> None:
    size = log_path.stat().st_size if log_path.exists() else 0
    prefix = b""
    with log_path.open("rb") as log:
        if size > EVIDENCE_TAIL_BYTES:
            log.seek(-EVIDENCE_TAIL_BYTES, os.SEEK_END)
            prefix = b"[earlier output omitted; full log retained on runner]\n"
        content = log.read(EVIDENCE_TAIL_BYTES)
    destination.write_bytes(prefix + content)


def _process_group_has_members(process: subprocess.Popen[bytes]) -> bool:
    process.poll()
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group_exit(
    process: subprocess.Popen[bytes], timeout: float
) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_has_members(process):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))
    return True


class _WindowsProcessJob:
    """Own a test process and descendants even if the direct child exits first."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class ThreadEntry32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ThreadID", wintypes.DWORD),
                ("th32OwnerProcessID", wintypes.DWORD),
                ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
            ]

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self._ctypes = ctypes
        self._wintypes = wintypes
        self._thread_entry_type = ThreadEntry32
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
        )
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.CreateToolhelp32Snapshot.argtypes = (
            wintypes.DWORD,
            wintypes.DWORD,
        )
        self._kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self._kernel32.Thread32First.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(ThreadEntry32),
        )
        self._kernel32.Thread32First.restype = wintypes.BOOL
        self._kernel32.Thread32Next.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(ThreadEntry32),
        )
        self._kernel32.Thread32Next.restype = wintypes.BOOL
        self._kernel32.OpenThread.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        self._kernel32.OpenThread.restype = wintypes.HANDLE
        self._kernel32.ResumeThread.argtypes = (wintypes.HANDLE,)
        self._kernel32.ResumeThread.restype = wintypes.DWORD
        self._kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self._kernel32.TerminateJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self._kernel32.CloseHandle.restype = wintypes.BOOL

        self._handle = self._kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())

        limits = ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = 0x00002000
        if not self._kernel32.SetInformationJobObject(
            self._handle,
            9,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = ctypes.get_last_error()
            self.close()
            raise ctypes.WinError(error)

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        process_handle = self._wintypes.HANDLE(int(process._handle))
        if not self._kernel32.AssignProcessToJobObject(self._handle, process_handle):
            raise self._ctypes.WinError(self._ctypes.get_last_error())

    def resume_initial_thread(self, process: subprocess.Popen[bytes]) -> None:
        snapshot = self._kernel32.CreateToolhelp32Snapshot(
            WINDOWS_TH32CS_SNAPTHREAD,
            0,
        )
        invalid_handle = self._ctypes.c_void_p(-1).value
        if not snapshot or int(snapshot) == invalid_handle:
            raise self._ctypes.WinError(self._ctypes.get_last_error())

        thread_id: int | None = None
        entry = self._thread_entry_type()
        entry.dwSize = self._ctypes.sizeof(entry)
        try:
            if not self._kernel32.Thread32First(snapshot, self._ctypes.byref(entry)):
                error = self._ctypes.get_last_error()
                if error != WINDOWS_ERROR_NO_MORE_FILES:
                    raise self._ctypes.WinError(error)
            else:
                while True:
                    if entry.th32OwnerProcessID == process.pid:
                        if thread_id is not None:
                            raise VerificationError(
                                "suspended verifier process had multiple initial threads"
                            )
                        thread_id = entry.th32ThreadID
                    if not self._kernel32.Thread32Next(
                        snapshot,
                        self._ctypes.byref(entry),
                    ):
                        error = self._ctypes.get_last_error()
                        if error != WINDOWS_ERROR_NO_MORE_FILES:
                            raise self._ctypes.WinError(error)
                        break
        finally:
            self._kernel32.CloseHandle(snapshot)

        if thread_id is None:
            raise VerificationError("unable to find the suspended verifier thread")
        thread_handle = self._kernel32.OpenThread(
            WINDOWS_THREAD_SUSPEND_RESUME,
            False,
            thread_id,
        )
        if not thread_handle:
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        try:
            previous_suspend_count = self._kernel32.ResumeThread(thread_handle)
            if previous_suspend_count == 0xFFFFFFFF:
                raise self._ctypes.WinError(self._ctypes.get_last_error())
            if previous_suspend_count != 1:
                raise VerificationError(
                    "suspended verifier thread had an unexpected suspend count"
                )
        finally:
            self._kernel32.CloseHandle(thread_handle)

    def terminate(self) -> None:
        if self._handle and not self._kernel32.TerminateJobObject(self._handle, 1):
            raise self._ctypes.WinError(self._ctypes.get_last_error())

    def close(self) -> None:
        if self._handle:
            handle = self._handle
            self._handle = None
            if not self._kernel32.CloseHandle(handle):
                raise self._ctypes.WinError(self._ctypes.get_last_error())


def _taskkill_owned_tree(process: subprocess.Popen[bytes]) -> None:
    taskkill = shutil.which("taskkill")
    if taskkill:
        try:
            subprocess.run(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


def _stop_owned_process_tree(
    process: subprocess.Popen[bytes],
    job: _WindowsProcessJob | None = None,
) -> None:
    if job is not None:
        try:
            job.terminate()
        except OSError:
            _taskkill_owned_tree(process)
            job.close()
    elif os.name == "nt":
        _taskkill_owned_tree(process)
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if not _wait_for_process_group_exit(
            process,
            PROCESS_TERMINATION_GRACE_SECONDS,
        ):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if not _wait_for_process_group_exit(
                process,
                PROCESS_TERMINATION_FORCE_TIMEOUT_SECONDS,
            ):
                raise VerificationError(
                    f"owned process group {process.pid} did not exit after SIGKILL"
                )
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=PROCESS_TERMINATION_FORCE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        if job is not None:
            try:
                job.terminate()
            except OSError:
                _taskkill_owned_tree(process)
        elif os.name == "nt":
            _taskkill_owned_tree(process)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.kill()
        process.wait(timeout=PROCESS_TERMINATION_FORCE_TIMEOUT_SECONDS)


def run_test_command(
    spec: TestCommand,
    *,
    cwd: Path,
    task_root: Path,
    env: dict[str, str],
    deadline: float,
    poll_interval: float = POLL_INTERVAL_SECONDS,
    max_task_bytes: int = MAX_TASK_BYTES,
    min_free_bytes: int = MIN_FREE_BYTES,
    disk_usage: Callable[[str | os.PathLike[str]], Any] = shutil.disk_usage,
    echo_output: bool = True,
    reader_drain_timeout_seconds: float = 30,
) -> CommandResult:
    logs_dir = task_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{spec.name}.log"
    if log_path.exists():
        raise VerificationError(f"refusing to overwrite existing log: {log_path}")
    check_budgets(
        task_root,
        max_task_bytes=max_task_bytes,
        min_free_bytes=min_free_bytes,
        disk_usage=disk_usage,
    )

    job = _WindowsProcessJob() if os.name == "nt" else None
    creationflags = (
        subprocess.CREATE_NEW_PROCESS_GROUP | WINDOWS_CREATE_SUSPENDED
        if os.name == "nt"
        else 0
    )
    process: subprocess.Popen[bytes] | None = None
    job_assigned = False
    try:
        process = subprocess.Popen(
            list(spec.argv),
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            creationflags=creationflags,
            start_new_session=(os.name != "nt"),
        )
        if job is not None:
            job.assign(process)
            job_assigned = True
            job.resume_initial_thread(process)
    except BaseException:
        try:
            if process is not None:
                if job is not None and job_assigned:
                    try:
                        job.terminate()
                    except OSError:
                        _taskkill_owned_tree(process)
                else:
                    _taskkill_owned_tree(process)
                if process.poll() is None:
                    process.kill()
                try:
                    process.wait(timeout=PROCESS_TERMINATION_FORCE_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    if job is not None and job_assigned:
                        job.terminate()
                    else:
                        _taskkill_owned_tree(process)
                    process.kill()
                    process.wait(timeout=PROCESS_TERMINATION_FORCE_TIMEOUT_SECONDS)
        finally:
            if process is not None and process.stdout is not None:
                process.stdout.close()
            if job is not None:
                job.close()
        raise
    assert process is not None
    read_error: list[str] = []

    try:

        def drain_output() -> None:
            try:
                assert process.stdout is not None
                with log_path.open("wb") as log:
                    while chunk := process.stdout.read(64 * 1024):
                        try:
                            log.write(chunk)
                            log.flush()
                        except OSError as exc:
                            if not read_error:
                                read_error.append(f"unable to write test log: {exc}")
                        if echo_output:
                            try:
                                sys.stdout.buffer.write(chunk)
                                sys.stdout.buffer.flush()
                            except (AttributeError, BrokenPipeError, OSError):
                                pass
            except OSError as exc:
                read_error.append(f"unable to read test output: {exc}")
            finally:
                if process.stdout is not None:
                    process.stdout.close()

        reader = threading.Thread(
            target=drain_output, name=f"log-{spec.name}", daemon=True
        )
        reader.start()
        started = time.monotonic()
        command_error: str | None = None
        while process.poll() is None:
            if read_error:
                command_error = read_error[0]
            elif time.monotonic() >= deadline:
                command_error = "55-minute process deadline exceeded"
            else:
                try:
                    check_budgets(
                        task_root,
                        max_task_bytes=max_task_bytes,
                        min_free_bytes=min_free_bytes,
                        disk_usage=disk_usage,
                    )
                except ResourceLimitError as exc:
                    command_error = str(exc)
            if command_error:
                _stop_owned_process_tree(process, job)
                break
            time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))

        if process.poll() is None:
            _stop_owned_process_tree(process, job)
        else:
            process.wait()
            if os.name != "nt" and _process_group_has_members(process):
                _stop_owned_process_tree(process)
        reader.join(timeout=reader_drain_timeout_seconds)
        if reader.is_alive():
            _stop_owned_process_tree(process, job)
            reader.join(timeout=5)
        if reader.is_alive():
            command_error = command_error or "test output reader did not stop"

        try:
            log_bytes, log_sha256 = _hash_file(log_path)
            summary = parse_test_summary(log_path)
        except OSError as exc:
            log_bytes, log_sha256, summary = 0, None, None
            command_error = command_error or f"unable to inspect test log: {exc}"
        try:
            check_budgets(
                task_root,
                max_task_bytes=max_task_bytes,
                min_free_bytes=min_free_bytes,
                disk_usage=disk_usage,
            )
        except ResourceLimitError as exc:
            command_error = command_error or str(exc)

        result = CommandResult(
            name=spec.name,
            command=list(spec.argv),
            return_code=process.returncode,
            duration_seconds=round(time.monotonic() - started, 3),
            log_path=str(log_path),
            log_bytes=log_bytes,
            log_sha256=log_sha256,
            summary=summary,
            error=command_error,
        )
        if command_error:
            raise ResourceLimitError(
                f"{spec.name}: {command_error}",
                result=result,
            )
        return result
    except BaseException:
        _stop_owned_process_tree(process, job)
        raise
    finally:
        if job is not None:
            job.close()


def _write_env_file(task_root: Path) -> dict[str, str]:
    directories = {
        "CONTRIB_TASK_ROOT": task_root,
        "CARGO_HOME": task_root / "cargo-home",
        "RUSTUP_HOME": task_root / "rustup-home",
        "CARGO_TARGET_DIR": task_root / "cargo-target",
        "TMP": task_root / "temp",
        "TEMP": task_root / "temp",
        "TMPDIR": task_root / "temp",
    }
    for path in directories.values():
        path.mkdir(parents=True, exist_ok=True)

    values = {name: str(path) for name, path in directories.items()}
    values.update(MANAGED_CARGO_ENV)
    env_file = os.environ.get("GITHUB_ENV")
    if not env_file:
        raise VerificationError("GITHUB_ENV is required to prepare the runner")
    with Path(env_file).open("a", encoding="utf-8", newline="\n") as output:
        for name, value in values.items():
            if "\n" in value or "\r" in value:
                raise VerificationError(f"invalid newline in {name}")
            output.write(f"{name}={value}\n")
    return values


def prepare_environment(task_root_text: str) -> None:
    platform_name = sys.platform
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise VerificationError("RUNNER_TEMP is required")
    validate_task_root(task_root_text, runner_temp, platform_name=platform_name)
    runner_temp_path = Path(runner_temp).resolve()
    task_root = Path(task_root_text).resolve()
    if not runner_temp_path.is_dir():
        raise VerificationError(f"RUNNER_TEMP does not exist: {runner_temp_path}")
    if task_root.exists():
        raise VerificationError(f"refusing to reuse task root: {task_root}")
    if shutil.disk_usage(runner_temp_path).free < MIN_FREE_BYTES:
        raise ResourceLimitError(
            f"RUNNER_TEMP has less than {MIN_FREE_BYTES} bytes free"
        )
    task_root.mkdir(parents=False, exist_ok=False)
    values = _write_env_file(task_root)
    used, free = check_budgets(task_root)
    print(
        json.dumps(
            {
                "task_root": str(task_root),
                "task_bytes": used,
                "free_bytes": free,
                "max_task_bytes": MAX_TASK_BYTES,
                "minimum_free_bytes": MIN_FREE_BYTES,
                "managed_paths": {
                    name: values[name]
                    for name in (
                        "CONTRIB_TASK_ROOT",
                        "CARGO_HOME",
                        "RUSTUP_HOME",
                        "CARGO_TARGET_DIR",
                        "TMP",
                    )
                },
            },
            indent=2,
        )
    )


def _validate_managed_environment(task_root: Path) -> dict[str, str]:
    expected = {
        "CONTRIB_TASK_ROOT": task_root,
        "CARGO_HOME": task_root / "cargo-home",
        "RUSTUP_HOME": task_root / "rustup-home",
        "CARGO_TARGET_DIR": task_root / "cargo-target",
        "TMP": task_root / "temp",
        "TEMP": task_root / "temp",
        "TMPDIR": task_root / "temp",
    }
    resolved_root = task_root.resolve()
    for name, expected_path in expected.items():
        value = os.environ.get(name)
        if not value:
            raise VerificationError(f"{name} is not set")
        resolved_value = Path(value).resolve()
        if resolved_value != expected_path.resolve():
            raise VerificationError(f"{name} is not bound to the task root")
        if (
            not _is_within(resolved_value, resolved_root)
            and name != "CONTRIB_TASK_ROOT"
        ):
            raise VerificationError(f"{name} escaped the task root")
        if sys.platform == "win32" and PureWindowsPath(value).drive.casefold() != "d:":
            raise VerificationError(f"{name} must stay on D:")
    for name, expected_value in MANAGED_CARGO_ENV.items():
        if os.environ.get(name) != expected_value:
            raise VerificationError(
                f"{name} must be {expected_value} for bounded builds"
            )
    return os.environ.copy()


def _verify_toolchain(repo_root: Path) -> dict[str, str]:
    toolchain_path = repo_root / "codex-rs" / "rust-toolchain.toml"
    if not toolchain_path.is_file():
        raise VerificationError(f"missing Rust toolchain pin: {toolchain_path}")
    with toolchain_path.open("rb") as source:
        toolchain = tomllib.load(source)
    channel = toolchain.get("toolchain", {}).get("channel")
    if channel != RUST_VERSION:
        raise VerificationError(
            f"workflow expects Rust {RUST_VERSION}, repo pins {channel!r}"
        )
    versions: dict[str, str] = {}
    for name in ("rustc", "cargo"):
        completed = subprocess.run(
            [name, "--version"],
            cwd=repo_root / "codex-rs",
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        version = completed.stdout.strip()
        if RUST_VERSION not in version:
            raise VerificationError(
                f"{name} version does not match repo pin {RUST_VERSION}: {version}"
            )
        versions[name] = version
    return versions


def _git_sha(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    sha = completed.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise VerificationError(f"unexpected checkout SHA: {sha!r}")
    expected_sha = os.environ.get("GITHUB_SHA")
    if expected_sha and sha != expected_sha:
        raise VerificationError(
            f"checkout SHA {sha} does not match event SHA {expected_sha}"
        )
    return sha


def _summary_dict(summary: TestSummary | None) -> dict[str, int | str] | None:
    if summary is None:
        return None
    return {**asdict(summary), "executed": summary.executed}


def run_verification(
    task_root_text: str,
    requested_tests: Sequence[str] | None = None,
) -> int:
    platform_name = sys.platform
    requested_names = None if requested_tests is None else list(requested_tests)
    commands = select_test_commands(platform_name, requested_names)
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise VerificationError("RUNNER_TEMP is required")
    validate_task_root(task_root_text, runner_temp, platform_name=platform_name)
    task_root = Path(task_root_text).resolve()
    env = _validate_managed_environment(task_root)
    repo_root = Path.cwd().resolve()
    cargo_root = repo_root / "codex-rs"
    if not (cargo_root / "Cargo.toml").is_file():
        raise VerificationError("run this script from the repository root")

    started_at = utc_now()
    receipt: dict[str, object] = {
        "schema_version": 1,
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "event_sha": os.environ.get("GITHUB_SHA"),
        "checkout_sha": None,
        "runner_os": platform_name,
        "started_at": started_at,
        "finished_at": None,
        "rust_toolchain_pin": RUST_VERSION,
        "verification_scope": (
            "platform_catalog" if requested_names is None else "selected_commands_only"
        ),
        "requested_tests": requested_names,
        "selected_tests": [spec.name for spec in commands],
        "tool_versions": {},
        "budgets": {
            "max_task_bytes": MAX_TASK_BYTES,
            "min_free_bytes": MIN_FREE_BYTES,
            "process_deadline_seconds": PROCESS_TIMEOUT_SECONDS,
            "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        },
        "task_root": str(task_root),
        "tests": [],
        "errors": [],
        "result": "failed",
    }
    evidence_dir = task_root / "evidence"
    tails_dir = evidence_dir / "tails"
    logs_dir = task_root / "logs"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    tails_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = evidence_dir / "verification.json"
    exit_code = 1

    def write_receipt() -> None:
        receipt["finished_at"] = utc_now()
        temporary_path = receipt_path.with_suffix(".json.tmp")
        temporary_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary_path.replace(receipt_path)

    try:
        used, free = check_budgets(task_root)
        receipt["initial_storage"] = {"task_bytes": used, "free_bytes": free}
        receipt["checkout_sha"] = _git_sha(repo_root)
        receipt["tool_versions"] = _verify_toolchain(repo_root)
        print(
            f"Verifying {receipt['checkout_sha']} on {platform_name}; "
            f"task storage {used}/{MAX_TASK_BYTES} bytes, {free} bytes free."
        )
        deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
        failures: list[str] = []
        results: list[dict[str, object]] = []
        for spec in commands:
            if time.monotonic() >= deadline:
                failures.append("55-minute process deadline exceeded")
                break
            print(f"\n== {spec.name}: {' '.join(spec.argv)} ==")
            try:
                result = run_test_command(
                    spec,
                    cwd=cargo_root,
                    task_root=task_root,
                    env=env,
                    deadline=deadline,
                )
            except ResourceLimitError as exc:
                failure_result = getattr(exc, "result", None)
                if failure_result is not None:
                    results.append(
                        {
                            **asdict(failure_result),
                            "summary": _summary_dict(failure_result.summary),
                        }
                    )
                    _write_bounded_tail(
                        Path(failure_result.log_path),
                        tails_dir / f"{failure_result.name}.txt",
                    )
                failures.append(str(exc))
                receipt["tests"] = results
                receipt["errors"] = failures
                write_receipt()
                break

            try:
                validate_test_result(result)
            except VerificationError as exc:
                failures.append(str(exc))
            tail_path = tails_dir / f"{result.name}.txt"
            _write_bounded_tail(Path(result.log_path), tail_path)
            results.append(
                {
                    **asdict(result),
                    "summary": _summary_dict(result.summary),
                    "evidence_tail": str(tail_path),
                }
            )
            receipt["tests"] = results
            receipt["errors"] = failures
            try:
                storage_used, free_bytes = check_budgets(task_root)
                receipt["last_storage"] = {
                    "task_bytes": storage_used,
                    "free_bytes": free_bytes,
                }
            except ResourceLimitError as exc:
                failures.append(str(exc))
                receipt["errors"] = failures
                write_receipt()
                break
            write_receipt()
        else:
            if not failures and len(results) == len(commands):
                receipt["result"] = "passed"
                exit_code = 0
        receipt["tests"] = results
        receipt["errors"] = failures
        if failures:
            receipt["result"] = "failed"
    except (
        OSError,
        subprocess.SubprocessError,
        VerificationError,
        tomllib.TOMLDecodeError,
    ) as exc:
        errors = receipt.setdefault("errors", [])
        assert isinstance(errors, list)
        errors.append(str(exc))
        print(f"verification setup failed: {exc}", file=sys.stderr)
    finally:
        try:
            used, free = check_budgets(task_root)
            receipt["final_storage"] = {
                "task_bytes": used,
                "free_bytes": free,
            }
        except (OSError, ResourceLimitError) as exc:
            errors = receipt.setdefault("errors", [])
            assert isinstance(errors, list)
            errors.append(str(exc))
            receipt["result"] = "failed"
            exit_code = 1
        write_receipt()

    print(f"Verification result: {receipt['result']}")
    print(f"Bounded evidence: {receipt_path}")
    if receipt["result"] != "passed":
        exit_code = 1
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare-environment", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--task-root", required=True)
    parser.add_argument("--tests", nargs="+", metavar="NAME")
    args = parser.parse_args(argv)
    if args.tests is not None and not args.run:
        parser.error("--tests may be used only with --run")
    try:
        if args.prepare_environment:
            prepare_environment(args.task_root)
            return 0
        return run_verification(args.task_root, requested_tests=args.tests)
    except (OSError, VerificationError, tomllib.TOMLDecodeError) as exc:
        print(f"contribution verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
