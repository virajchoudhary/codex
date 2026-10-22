import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import NamedTuple
from unittest.mock import patch

import run_contribution_verification
from run_contribution_verification import (
    CommandResult,
    ResourceLimitError,
    TestCommand as CommandSpec,
    VerificationError,
    build_test_commands,
    check_budgets,
    parse_test_summary,
    run_test_command,
    validate_task_root,
    validate_test_result,
)


class DiskUsage(NamedTuple):
    total: int
    used: int
    free: int


def _windows_process_is_running(pid: int) -> bool:
    result = subprocess.run(
        ["tasklist.exe", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return f'"{pid}"' in result.stdout


def _stop_windows_process_tree(pid: int) -> None:
    subprocess.run(
        ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=15,
    )
    deadline = time.monotonic() + 5
    while _windows_process_is_running(pid) and time.monotonic() < deadline:
        time.sleep(0.05)


def _posix_process_state(pid: int) -> str:
    result = subprocess.run(
        ["ps", "-o", "state=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return result.stdout.strip()


def _posix_process_is_running(pid: int) -> bool:
    state = _posix_process_state(pid)
    return bool(state) and not state.startswith("Z")


class RunContributionVerificationTest(unittest.TestCase):
    def test_rejects_windows_task_root_on_c_drive(self) -> None:
        with self.assertRaisesRegex(VerificationError, "must stay on D"):
            validate_task_root(
                r"C:\runner\_temp\contribution",
                r"D:\runner\_temp",
                platform_name="win32",
            )

    def test_windows_task_root_must_be_inside_runner_temp(self) -> None:
        with self.assertRaisesRegex(VerificationError, "inside RUNNER_TEMP"):
            validate_task_root(
                r"D:\other\contribution",
                r"D:\runner\_temp",
                platform_name="win32",
            )

    def test_accepts_d_task_root_inside_runner_temp(self) -> None:
        runner_temp = r"D:\CodexDisposableBuild\contribution-verification-unit-tests"
        validate_task_root(
            runner_temp + r"\run",
            runner_temp,
            platform_name="win32",
        )

    def test_zero_test_summary_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "zero-tests.log"
            log_path.write_text(
                "running 0 tests\n"
                "test result: ok. 0 passed; 0 failed; 0 ignored; "
                "0 measured; 0 filtered out; finished in 0.00s\n",
                encoding="utf-8",
            )
            result = CommandResult(
                name="zero-tests",
                command=["cargo", "test"],
                return_code=0,
                duration_seconds=0.01,
                log_path=str(log_path),
                log_bytes=log_path.stat().st_size,
                log_sha256=None,
                summary=parse_test_summary(log_path),
            )
            with self.assertRaisesRegex(VerificationError, "no tests executed"):
                validate_test_result(result)

    def test_profile_incremental_environment_uses_cargo_boolean_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            env_file = root / "github-env"
            with patch.dict(os.environ, {"GITHUB_ENV": str(env_file)}):
                values = run_contribution_verification._write_env_file(root)
            self.assertEqual(values["CARGO_INCREMENTAL"], "0")
            for name in (
                "CARGO_PROFILE_DEV_INCREMENTAL",
                "CARGO_PROFILE_TEST_INCREMENTAL",
            ):
                self.assertEqual(values[name], "false")
                self.assertIn(f"{name}=false\n", env_file.read_text(encoding="utf-8"))
            with patch.dict(os.environ, values):
                run_contribution_verification._validate_managed_environment(root)
                for name in (
                    "CARGO_PROFILE_DEV_INCREMENTAL",
                    "CARGO_PROFILE_TEST_INCREMENTAL",
                ):
                    with self.subTest(name=name), patch.dict(os.environ, {name: "0"}):
                        with self.assertRaisesRegex(
                            VerificationError, f"{name} must be"
                        ):
                            run_contribution_verification._validate_managed_environment(
                                root
                            )

    def test_failed_test_output_and_log_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            task_root = Path(temp_dir)
            output = (
                "test sample::regression ... FAILED\n"
                "test result: FAILED. 0 passed; 1 failed; 0 ignored; "
                "0 measured; 3 filtered out; finished in 0.01s\n"
            )
            code = f"import sys; sys.stdout.write({output!r}); sys.stdout.flush(); sys.exit(101)"
            result = run_test_command(
                CommandSpec("failing-regression", (sys.executable, "-c", code)),
                cwd=task_root,
                task_root=task_root,
                env=os.environ.copy(),
                deadline=10**12,
                poll_interval=0.01,
                max_task_bytes=1024 * 1024,
                min_free_bytes=0,
                echo_output=False,
            )

            with self.assertRaisesRegex(VerificationError, "test command failed"):
                validate_test_result(result)
            log_path = Path(result.log_path)
            self.assertTrue(log_path.is_file())
            self.assertIn(
                "sample::regression ... FAILED", log_path.read_text(encoding="utf-8")
            )
            self.assertEqual(result.return_code, 101)
            self.assertEqual(result.summary.failed, 1)
            self.assertIsNotNone(result.log_sha256)

    def test_storage_budget_rejects_task_output_over_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "output.bin").write_bytes(b"12345")
            with self.assertRaisesRegex(ResourceLimitError, "storage exceeded"):
                check_budgets(root, max_task_bytes=4, min_free_bytes=0)

    def test_storage_budget_enforces_free_space_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            usage = DiskUsage(total=100, used=90, free=10)

            def fake_disk_usage(_path: str | os.PathLike[str]) -> DiskUsage:
                return usage

            with self.assertRaisesRegex(ResourceLimitError, "reserve breached"):
                check_budgets(
                    Path(temp_dir),
                    max_task_bytes=100,
                    min_free_bytes=11,
                    disk_usage=fake_disk_usage,
                )

    def test_free_space_breach_stops_owned_process_and_keeps_log(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            task_root = Path(temp_dir)
            calls = 0

            def shrinking_disk_usage(_path: str | os.PathLike[str]) -> DiskUsage:
                nonlocal calls
                calls += 1
                free = 100 if calls < 10 else 0
                return DiskUsage(total=100, used=100 - free, free=free)

            code = (
                "import time; print('owned child started', flush=True); time.sleep(10)"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(
                ResourceLimitError, "reserve breached"
            ) as raised:
                run_test_command(
                    CommandSpec("budget-breach", (sys.executable, "-c", code)),
                    cwd=task_root,
                    task_root=task_root,
                    env=os.environ.copy(),
                    deadline=time.monotonic() + 10,
                    poll_interval=0.02,
                    max_task_bytes=1024 * 1024,
                    min_free_bytes=1,
                    disk_usage=shrinking_disk_usage,
                    echo_output=False,
                )

            self.assertLess(time.monotonic() - started, 5)
            self.assertIsNotNone(raised.exception.result)
            log_path = Path(raised.exception.result.log_path)
            self.assertTrue(log_path.is_file())
            self.assertIn("owned child started", log_path.read_text(encoding="utf-8"))

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects are platform-specific")
    def test_job_object_kills_descendant_after_direct_child_exits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            task_root = Path(temp_dir)
            child_code = "import time; time.sleep(30)"
            parent_code = (
                "import subprocess,sys; "
                "subprocess.Popen([sys.executable, '-c', sys.argv[1]]); "
                "print('parent exited', flush=True)"
            )
            started = time.monotonic()
            result = run_test_command(
                CommandSpec(
                    "exited-parent-descendant",
                    (sys.executable, "-c", parent_code, child_code),
                ),
                cwd=task_root,
                task_root=task_root,
                env=os.environ.copy(),
                deadline=time.monotonic() + 10,
                min_free_bytes=0,
                echo_output=False,
                reader_drain_timeout_seconds=0.1,
            )
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(result.return_code, 0)
            self.assertIn(
                "parent exited", Path(result.log_path).read_text(encoding="utf-8")
            )

    @unittest.skipUnless(
        os.name == "nt", "Windows process startup is platform-specific"
    )
    def test_windows_startup_failures_terminate_the_suspended_child(self) -> None:
        original_assign = run_contribution_verification._WindowsProcessJob.assign
        for stage in ("assignment", "resume"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temp_dir:
                task_root = Path(temp_dir)
                marker_path = task_root / "executed.marker"
                process_ids: list[int] = []
                code = (
                    "import pathlib,sys,time; "
                    "pathlib.Path(sys.argv[1]).write_text('executed', encoding='ascii'); "
                    "time.sleep(30)"
                )

                def assign(
                    job: run_contribution_verification._WindowsProcessJob,
                    process: subprocess.Popen[bytes],
                    *,
                    stage: str = stage,
                    marker_path: Path = marker_path,
                    process_ids: list[int] = process_ids,
                ) -> None:
                    process_ids.append(process.pid)
                    if stage == "assignment":
                        self.assertFalse(marker_path.exists())
                        raise OSError("synthetic assignment failure")
                    original_assign(job, process)

                def fail_resume(
                    _job: run_contribution_verification._WindowsProcessJob,
                    _process: subprocess.Popen[bytes],
                    *,
                    marker_path: Path = marker_path,
                ) -> None:
                    self.assertFalse(marker_path.exists())
                    raise OSError("synthetic resume failure")

                with (
                    patch.object(
                        run_contribution_verification._WindowsProcessJob,
                        "assign",
                        assign,
                    ),
                    patch.object(
                        run_contribution_verification._WindowsProcessJob,
                        "resume_initial_thread",
                        fail_resume,
                    ),
                ):
                    with self.assertRaisesRegex(
                        OSError,
                        f"synthetic {stage} failure",
                    ):
                        run_test_command(
                            CommandSpec(
                                f"startup-failure-{stage}",
                                (sys.executable, "-c", code, str(marker_path)),
                            ),
                            cwd=task_root,
                            task_root=task_root,
                            env=os.environ.copy(),
                            deadline=time.monotonic() + 10,
                            min_free_bytes=0,
                            echo_output=False,
                        )
                self.assertEqual(len(process_ids), 1)
                self.assertFalse(marker_path.exists())
                self.assertFalse(
                    _windows_process_is_running(process_ids[0]),
                    f"Windows test process {process_ids[0]} survived {stage} failure",
                )

    @unittest.skipUnless(
        os.name == "nt", "Windows process startup is platform-specific"
    )
    def test_windows_child_waits_for_job_assignment_before_it_can_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            task_root = Path(temp_dir)
            parent_pid_path = task_root / "parent.pid"
            child_pid_path = task_root / "child.pid"
            child_code = (
                "import os,pathlib,sys,time; "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
                "time.sleep(30)"
            )
            parent_code = (
                "import os,pathlib,subprocess,sys,time\n"
                "pathlib.Path(sys.argv[3]).write_text(str(os.getpid()), encoding='ascii')\n"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])\n"
                "deadline=time.monotonic()+5\n"
                "while not pathlib.Path(sys.argv[2]).exists() and time.monotonic()<deadline:\n"
                "    time.sleep(0.01)\n"
                "if not pathlib.Path(sys.argv[2]).exists():\n"
                "    raise SystemExit('child not ready')\n"
                "print('parent spawned descendant', flush=True)\n"
                "time.sleep(30)\n"
            )
            original_assign = run_contribution_verification._WindowsProcessJob.assign
            command_result: CommandResult | None = None

            def delayed_assign(
                job: run_contribution_verification._WindowsProcessJob,
                process: subprocess.Popen[bytes],
            ) -> None:
                deadline = time.monotonic() + 1
                while not child_pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(parent_pid_path.exists())
                self.assertFalse(child_pid_path.exists())
                original_assign(job, process)

            try:
                with patch.object(
                    run_contribution_verification._WindowsProcessJob,
                    "assign",
                    delayed_assign,
                ):
                    with self.assertRaisesRegex(
                        ResourceLimitError, "process deadline"
                    ) as raised:
                        run_test_command(
                            CommandSpec(
                                "suspended-job-assignment",
                                (
                                    sys.executable,
                                    "-c",
                                    parent_code,
                                    child_code,
                                    str(child_pid_path),
                                    str(parent_pid_path),
                                ),
                            ),
                            cwd=task_root,
                            task_root=task_root,
                            env=os.environ.copy(),
                            deadline=time.monotonic() + 3,
                            poll_interval=0.02,
                            max_task_bytes=1024 * 1024,
                            min_free_bytes=0,
                            echo_output=False,
                            reader_drain_timeout_seconds=0.1,
                        )
                command_result = raised.exception.result
                self.assertIsNotNone(command_result)
                assert command_result is not None
                self.assertTrue(parent_pid_path.is_file())
                self.assertTrue(child_pid_path.is_file())
                self.assertIn(
                    "parent spawned descendant",
                    Path(command_result.log_path).read_text(encoding="utf-8"),
                )
            finally:
                recorded_pids = [
                    int(path.read_text(encoding="ascii"))
                    for path in (parent_pid_path, child_pid_path)
                    if path.is_file()
                ]
                for pid in recorded_pids:
                    _stop_windows_process_tree(pid)
                for pid in recorded_pids:
                    self.assertFalse(
                        _windows_process_is_running(pid),
                        f"Windows test process {pid} survived cleanup",
                    )

    @unittest.skipUnless(os.name != "nt", "POSIX process groups are platform-specific")
    def test_process_group_kills_term_ignoring_descendant_after_leader_exits(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            task_root = Path(temp_dir)
            parent_pid_path = task_root / "parent.pid"
            child_pid_path = task_root / "child.pid"
            child_code = (
                "import os,pathlib,signal,sys,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
                "print('descendant ignores TERM', flush=True); "
                "time.sleep(30)"
            )
            parent_code = (
                "import os,pathlib,subprocess,sys,time\n"
                "pathlib.Path(sys.argv[3]).write_text(str(os.getpid()), encoding='ascii')\n"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])\n"
                "deadline=time.monotonic()+5\n"
                "while not pathlib.Path(sys.argv[2]).exists() and time.monotonic()<deadline:\n"
                "    time.sleep(0.01)\n"
                "if not pathlib.Path(sys.argv[2]).exists():\n"
                "    raise SystemExit('child not ready')\n"
                "print('leader exited', flush=True)\n"
            )
            try:
                with patch.object(
                    run_contribution_verification,
                    "PROCESS_TERMINATION_GRACE_SECONDS",
                    0.2,
                ):
                    result = run_test_command(
                        CommandSpec(
                            "term-resistant-descendant",
                            (
                                sys.executable,
                                "-c",
                                parent_code,
                                child_code,
                                str(child_pid_path),
                                str(parent_pid_path),
                            ),
                        ),
                        cwd=task_root,
                        task_root=task_root,
                        env=os.environ.copy(),
                        deadline=time.monotonic() + 10,
                        poll_interval=0.02,
                        max_task_bytes=1024 * 1024,
                        min_free_bytes=0,
                        echo_output=False,
                        reader_drain_timeout_seconds=0.1,
                    )
                self.assertEqual(result.return_code, 0)
                self.assertIsNone(result.error)
                self.assertTrue(parent_pid_path.is_file())
                self.assertTrue(child_pid_path.is_file())
                child_pid = int(child_pid_path.read_text(encoding="ascii"))
                log = Path(result.log_path).read_text(encoding="utf-8")
                self.assertIn("leader exited", log)
                self.assertIn("descendant ignores TERM", log)
                self.assertFalse(_posix_process_is_running(child_pid))
            finally:
                recorded_pids = [
                    int(path.read_text(encoding="ascii"))
                    for path in (parent_pid_path, child_pid_path)
                    if path.is_file()
                ]
                for pid in recorded_pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for pid in recorded_pids:
                    self.assertFalse(
                        _posix_process_is_running(pid),
                        f"POSIX test process {pid} survived cleanup",
                    )

    @unittest.skipUnless(os.name != "nt", "POSIX process groups are platform-specific")
    def test_process_group_cleans_term_ignoring_descendant_with_closed_stdout(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            task_root = Path(temp_dir)
            parent_pid_path = task_root / "parent.pid"
            child_pid_path = task_root / "child.pid"
            child_code = (
                "import os,pathlib,signal,sys,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
                "print('descendant closed stdout', flush=True); "
                "os.close(1); os.close(2); time.sleep(30)"
            )
            parent_code = (
                "import os,pathlib,subprocess,sys,time\n"
                "pathlib.Path(sys.argv[3]).write_text(str(os.getpid()), encoding='ascii')\n"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])\n"
                "deadline=time.monotonic()+5\n"
                "while not pathlib.Path(sys.argv[2]).exists() and time.monotonic()<deadline:\n"
                "    time.sleep(0.01)\n"
                "if not pathlib.Path(sys.argv[2]).exists():\n"
                "    raise SystemExit('child not ready')\n"
                "print('leader exited', flush=True)\n"
            )
            try:
                with patch.object(
                    run_contribution_verification,
                    "PROCESS_TERMINATION_GRACE_SECONDS",
                    0.2,
                ):
                    result = run_test_command(
                        CommandSpec(
                            "term-resistant-descendant-closed-stdout",
                            (
                                sys.executable,
                                "-c",
                                parent_code,
                                child_code,
                                str(child_pid_path),
                                str(parent_pid_path),
                            ),
                        ),
                        cwd=task_root,
                        task_root=task_root,
                        env=os.environ.copy(),
                        deadline=time.monotonic() + 10,
                        poll_interval=0.02,
                        max_task_bytes=1024 * 1024,
                        min_free_bytes=0,
                        echo_output=False,
                        reader_drain_timeout_seconds=0.1,
                    )
                self.assertEqual(result.return_code, 0)
                self.assertIsNone(result.error)
                self.assertTrue(parent_pid_path.is_file())
                self.assertTrue(child_pid_path.is_file())
                child_pid = int(child_pid_path.read_text(encoding="ascii"))
                log = Path(result.log_path).read_text(encoding="utf-8")
                self.assertIn("leader exited", log)
                self.assertIn("descendant closed stdout", log)
                self.assertFalse(_posix_process_is_running(child_pid))
            finally:
                recorded_pids = [
                    int(path.read_text(encoding="ascii"))
                    for path in (parent_pid_path, child_pid_path)
                    if path.is_file()
                ]
                for pid in recorded_pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for pid in recorded_pids:
                    self.assertFalse(
                        _posix_process_is_running(pid),
                        f"POSIX test process {pid} survived cleanup",
                    )

    @unittest.skipUnless(os.name != "nt", "POSIX process groups are platform-specific")
    def test_process_group_reaps_leader_before_escalating_to_live_descendant(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            task_root = Path(temp_dir)
            parent_pid_path = task_root / "parent.pid"
            child_pid_path = task_root / "child.pid"
            child_code = (
                "import os,pathlib,signal,sys,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
                "print('descendant ignores TERM', flush=True); "
                "time.sleep(30)"
            )
            parent_code = (
                "import os,pathlib,subprocess,sys,time\n"
                "pathlib.Path(sys.argv[3]).write_text(str(os.getpid()), encoding='ascii')\n"
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])\n"
                "deadline=time.monotonic()+5\n"
                "while not pathlib.Path(sys.argv[2]).exists() and time.monotonic()<deadline:\n"
                "    time.sleep(0.01)\n"
                "if not pathlib.Path(sys.argv[2]).exists():\n"
                "    raise SystemExit('child not ready')\n"
                "print('leader waiting for cleanup', flush=True)\n"
                "time.sleep(30)\n"
            )

            def disk_usage(_path: str | os.PathLike[str]) -> DiskUsage:
                free = 0 if child_pid_path.exists() else 100
                return DiskUsage(total=100, used=100 - free, free=free)

            started = time.monotonic()
            try:
                with patch.object(
                    run_contribution_verification,
                    "PROCESS_TERMINATION_GRACE_SECONDS",
                    0.2,
                ):
                    with self.assertRaisesRegex(
                        ResourceLimitError,
                        "reserve breached",
                    ) as raised:
                        run_test_command(
                            CommandSpec(
                                "term-resistant-descendant-with-live-leader",
                                (
                                    sys.executable,
                                    "-c",
                                    parent_code,
                                    child_code,
                                    str(child_pid_path),
                                    str(parent_pid_path),
                                ),
                            ),
                            cwd=task_root,
                            task_root=task_root,
                            env=os.environ.copy(),
                            deadline=time.monotonic() + 10,
                            poll_interval=0.02,
                            max_task_bytes=1024 * 1024,
                            min_free_bytes=1,
                            disk_usage=disk_usage,
                            echo_output=False,
                            reader_drain_timeout_seconds=0.1,
                        )
                self.assertLess(time.monotonic() - started, 5)
                result = raised.exception.result
                self.assertIsNotNone(result)
                assert result is not None
                self.assertTrue(parent_pid_path.is_file())
                self.assertTrue(child_pid_path.is_file())
                log = Path(result.log_path).read_text(encoding="utf-8")
                self.assertIn("leader waiting for cleanup", log)
                self.assertIn("descendant ignores TERM", log)
            finally:
                recorded_pids = [
                    int(path.read_text(encoding="ascii"))
                    for path in (parent_pid_path, child_pid_path)
                    if path.is_file()
                ]
                for pid in recorded_pids:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for pid in recorded_pids:
                    self.assertFalse(
                        _posix_process_is_running(pid),
                        f"POSIX test process {pid} survived cleanup",
                    )

    def test_mac_only_daemon_regression_is_not_scheduled_on_windows(self) -> None:
        windows = build_test_commands("win32")
        macos = build_test_commands("darwin")
        self.assertEqual(len(windows), 4)
        self.assertEqual(len(macos), 6)
        self.assertFalse(
            any(command.name == "app-server-daemon-selection" for command in windows)
        )
        self.assertEqual(
            sum(command.name == "app-server-daemon-selection" for command in macos),
            1,
        )
        self.assertEqual(
            sum(
                command.name == "hooks-command-runner-process-group"
                for command in macos
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
