use std::ffi::OsString;
use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use codex_config::config_toml::NotifyPayloadTransport;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use tokio::process::Command;
use tokio::time::timeout;

use crate::Hook;
use crate::HookEvent;
use crate::HookPayload;
use crate::HookResult;
use crate::registry::command_from_argv;

const NOTIFY_STDIN_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Legacy notify payload appended as the final argv argument for backward compatibility.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum UserNotification {
    #[serde(rename_all = "kebab-case")]
    AgentTurnComplete {
        thread_id: String,
        turn_id: String,
        cwd: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        client: Option<String>,
        input_messages: Vec<String>,
        last_assistant_message: Option<String>,
    },
}

pub fn legacy_notify_json(payload: &HookPayload) -> Result<String, serde_json::Error> {
    match &payload.hook_event {
        HookEvent::AfterAgent { event } => {
            serde_json::to_string(&UserNotification::AgentTurnComplete {
                thread_id: event.thread_id.to_string(),
                turn_id: event.turn_id.clone(),
                cwd: payload.cwd.display().to_string(),
                client: payload.client.clone(),
                input_messages: event.input_messages.clone(),
                last_assistant_message: event.last_assistant_message.clone(),
            })
        }
    }
}

// TODO: Remove this hook and its environment plumbing when legacy `notify` support is removed.
pub(crate) fn notify_hook(
    argv: Vec<String>,
    environment: Arc<Vec<(OsString, OsString)>>,
    transport: NotifyPayloadTransport,
) -> Hook {
    let argv = Arc::new(argv);
    Hook {
        name: "legacy_notify".to_string(),
        func: Arc::new(move |payload: &HookPayload| {
            let argv = Arc::clone(&argv);
            let environment = Arc::clone(&environment);
            Box::pin(async move {
                let notify_payload = legacy_notify_json(payload).ok();
                let Some(mut command) = notify_command(
                    &argv,
                    environment.iter().cloned(),
                    transport,
                    notify_payload.as_deref(),
                ) else {
                    return HookResult::Success;
                };

                match transport {
                    NotifyPayloadTransport::Argv => match command.spawn() {
                        Ok(_) => HookResult::Success,
                        Err(err) => HookResult::FailedContinue(err.into()),
                    },
                    NotifyPayloadTransport::Stdin => {
                        let child = match command.spawn() {
                            Ok(child) => child,
                            Err(err) => return HookResult::FailedContinue(err.into()),
                        };
                        let mut pending_child = PendingNotifyChild::new(child);

                        if let Some(notify_payload) = notify_payload {
                            match write_notify_payload(
                                pending_child.child_mut(),
                                notify_payload.as_bytes(),
                                NOTIFY_STDIN_WRITE_TIMEOUT,
                            )
                            .await
                            {
                                Ok(()) => {
                                    pending_child.disarm();
                                    HookResult::Success
                                }
                                Err(err) => HookResult::FailedContinue(err.into()),
                            }
                        } else {
                            drop(pending_child.child_mut().stdin.take());
                            pending_child.disarm();
                            HookResult::Success
                        }
                    }
                }
            })
        }),
    }
}

fn notify_command(
    argv: &[String],
    environment: impl IntoIterator<Item = (OsString, OsString)>,
    transport: NotifyPayloadTransport,
    payload: Option<&str>,
) -> Option<Command> {
    let mut command = command_from_argv(argv, environment)?;
    match transport {
        NotifyPayloadTransport::Argv => {
            if let Some(payload) = payload {
                command.arg(payload);
            }
            command.stdin(Stdio::null());
        }
        NotifyPayloadTransport::Stdin => {
            command.stdin(Stdio::piped());
        }
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    Some(command)
}

struct PendingNotifyChild {
    child: Option<Child>,
}

impl PendingNotifyChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("pending notify child should be present")
    }

    fn disarm(&mut self) {
        drop(self.child.take());
    }
}

impl Drop for PendingNotifyChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };

        let _ = child.start_kill();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}

async fn write_notify_payload(
    child: &mut Child,
    payload: &[u8],
    write_timeout: Duration,
) -> Result<(), io::Error> {
    let write_result = match child.stdin.as_mut() {
        Some(stdin) => match timeout(write_timeout, stdin.write_all(payload)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(io::Error::new(
                error.kind(),
                format!("notify stdin write failed: {}", error.kind()),
            )),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("notify stdin write timed out after {write_timeout:?}"),
            )),
        },
        None => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "notify stdin pipe is unavailable",
        )),
    };

    match write_result {
        Ok(()) => {
            drop(child.stdin.take());
            Ok(())
        }
        Err(error) => {
            drop(child.stdin.take());
            let _ = child.kill().await;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::path::Path;
    #[cfg(windows)]
    use std::path::PathBuf;
    use std::time::Instant;

    use anyhow::Result;
    use codex_protocol::ThreadId;
    use codex_protocol::shell_environment::CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN_ENV_VAR;
    use codex_utils_absolute_path::test_support::PathBufExt;
    use codex_utils_absolute_path::test_support::test_path_buf;
    use pretty_assertions::assert_eq;
    use serde_json::Value;
    use serde_json::json;
    use tempfile::TempDir;
    use tempfile::tempdir;
    use tokio::time::sleep;

    use super::*;
    use crate::HookEventAfterAgent;

    const FIXTURE_MODE_ENV: &str = "CODEX_NOTIFY_TEST_FIXTURE_MODE";
    const FIXTURE_RESULT_ENV: &str = "CODEX_NOTIFY_TEST_FIXTURE_RESULT";
    const FIXTURE_STARTED_ENV: &str = "CODEX_NOTIFY_TEST_FIXTURE_STARTED";
    #[cfg(not(windows))]
    const CHILD_FIXTURE_TEST: &str = "legacy_notify::tests::notify_child_fixture";

    fn notify_payload(input_message: String, last_assistant_message: String) -> HookPayload {
        HookPayload {
            session_id: ThreadId::new(),
            cwd: test_path_buf("/Users/example/project").abs(),
            client: Some("codex-tui".to_string()),
            triggered_at: chrono::Utc::now(),
            hook_event: HookEvent::AfterAgent {
                event: HookEventAfterAgent {
                    thread_id: ThreadId::from_string("b5f6c1c2-1111-2222-3333-444455556666")
                        .expect("valid thread id"),
                    turn_id: "12345".to_string(),
                    input_messages: vec![input_message],
                    last_assistant_message: Some(last_assistant_message),
                },
            },
        }
    }

    fn large_ascii_notify_payload() -> HookPayload {
        notify_payload(
            format!("{}-notify-payload-end", "x".repeat(54_000)),
            "short answer".to_string(),
        )
    }

    fn large_unicode_notify_payload() -> HookPayload {
        notify_payload(
            "short notification".to_string(),
            "\u{4e2d}\u{1f600}".repeat(20_000),
        )
    }

    fn fixture_argv(temp: &TempDir) -> Vec<String> {
        #[cfg(windows)]
        {
            let script_path = temp.path().join("notify-fixture.ps1");
            fs::write(
                &script_path,
                r#"param([string]$Notification)
$ErrorActionPreference = 'Stop'
switch ($env:CODEX_NOTIFY_TEST_FIXTURE_MODE) {
    'argv' {
        $payload = [string]$Notification
        [System.IO.File]::WriteAllBytes(
            $env:CODEX_NOTIFY_TEST_FIXTURE_RESULT,
            [System.Text.Encoding]::UTF8.GetBytes($payload)
        )
    }
    'stdin' {
        $inputStream = [Console]::OpenStandardInput()
        $buffer = New-Object System.IO.MemoryStream
        $inputStream.CopyTo($buffer)
        [System.IO.File]::WriteAllBytes(
            $env:CODEX_NOTIFY_TEST_FIXTURE_RESULT,
            $buffer.ToArray()
        )
    }
    'never-read' {
        [System.IO.File]::WriteAllText($env:CODEX_NOTIFY_TEST_FIXTURE_STARTED, [string]$PID)
        Start-Sleep -Seconds 30
    }
    'exit-before-read' {
        [System.IO.File]::WriteAllText($env:CODEX_NOTIFY_TEST_FIXTURE_STARTED, [string]$PID)
        Start-Sleep -Milliseconds 250
        exit 17
    }
    default { throw "unknown test fixture mode" }
}
"#,
            )
            .expect("write PowerShell notification fixture");
            let powershell = PathBuf::from(std::env::var_os("WINDIR").expect("WINDIR"))
                .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
            vec![
                powershell.to_string_lossy().into_owned(),
                "-NoLogo".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-File".to_string(),
                script_path.to_string_lossy().into_owned(),
            ]
        }

        #[cfg(not(windows))]
        {
            let _ = temp;
            vec![
                std::env::current_exe()
                    .expect("current test executable")
                    .to_string_lossy()
                    .into_owned(),
                "--exact".to_string(),
                CHILD_FIXTURE_TEST.to_string(),
                "--nocapture".to_string(),
            ]
        }
    }

    fn fixture_environment(
        temp: &TempDir,
        mode: &str,
        result_path: &Path,
    ) -> Arc<Vec<(OsString, OsString)>> {
        let mut environment = std::env::vars_os().collect::<Vec<_>>();
        environment.retain(|(name, _)| {
            name != FIXTURE_MODE_ENV && name != FIXTURE_RESULT_ENV && name != FIXTURE_STARTED_ENV
        });
        environment.push((OsString::from(FIXTURE_MODE_ENV), OsString::from(mode)));
        environment.push((
            OsString::from(FIXTURE_RESULT_ENV),
            result_path.as_os_str().to_os_string(),
        ));
        environment.push((
            OsString::from(FIXTURE_STARTED_ENV),
            temp.path().join("started").into_os_string(),
        ));
        Arc::new(environment)
    }

    async fn wait_for_file(path: &Path) -> Vec<u8> {
        timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(bytes) = fs::read(path)
                    && !bytes.is_empty()
                {
                    return bytes;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture should write its result")
    }

    async fn assert_fixture_delivery(result_path: &Path, expected: &[u8]) {
        let received = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(bytes) = fs::read(result_path)
                    && bytes.len() >= expected.len()
                {
                    return bytes;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture should write the full notification");
        assert_eq!(received, expected);
    }

    #[cfg(windows)]
    async fn assert_argv_payload_fails_with_win32_206(
        temp: &TempDir,
        argv: Vec<String>,
        payload: &HookPayload,
    ) {
        let result_path = temp.path().join("oversized-argv-result");
        let environment = fixture_environment(temp, "argv", &result_path);
        let hook = notify_hook(argv, environment, NotifyPayloadTransport::Argv);
        let response = timeout(Duration::from_secs(5), hook.execute(payload))
            .await
            .expect("argv hook spawn should be bounded");
        let HookResult::FailedContinue(error) = response.result else {
            panic!("oversized argv payload should fail non-fatally");
        };
        let raw_os_error = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error);
        assert_eq!(raw_os_error, Some(206));
        assert!(
            !result_path.exists(),
            "helper must not start for oversized argv"
        );
    }

    #[cfg(windows)]
    fn process_is_running(pid: u32) -> bool {
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .expect("query child process with tasklist");
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
    }

    #[cfg(unix)]
    fn process_is_running(pid: u32) -> bool {
        let output = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .output()
            .expect("query child process with ps");
        String::from_utf8_lossy(&output.stdout).trim() == pid.to_string()
    }

    async fn wait_for_process_exit(pid: u32) {
        timeout(Duration::from_secs(5), async {
            loop {
                if !process_is_running(pid) {
                    return;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("cancelled notify child should exit");
    }

    #[test]
    fn notify_child_fixture() {
        let Ok(mode) = std::env::var(FIXTURE_MODE_ENV) else {
            return;
        };
        let result_path = std::env::var_os(FIXTURE_RESULT_ENV).expect("fixture result path");
        let started_path = std::env::var_os(FIXTURE_STARTED_ENV).expect("fixture started path");

        match mode.as_str() {
            "stdin" => {
                let mut bytes = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut bytes)
                    .expect("read fixture stdin");
                fs::write(result_path, bytes).expect("write fixture bytes");
            }
            "never-read" => {
                fs::write(started_path, std::process::id().to_string())
                    .expect("write fixture process id");
                std::thread::sleep(Duration::from_secs(30));
            }
            "exit-before-read" => {
                fs::write(started_path, std::process::id().to_string())
                    .expect("write fixture process id");
                std::thread::sleep(Duration::from_millis(250));
                std::process::exit(17);
            }
            _ => panic!("unknown test fixture mode"),
        }
    }

    fn expected_notification_json() -> Value {
        let cwd = test_path_buf("/Users/example/project");
        json!({
            "type": "agent-turn-complete",
            "thread-id": "b5f6c1c2-1111-2222-3333-444455556666",
            "turn-id": "12345",
            "cwd": cwd.display().to_string(),
            "client": "codex-tui",
            "input-messages": ["Rename `foo` to `bar` and update the callsites."],
            "last-assistant-message": "Rename complete and verified `cargo build` succeeds.",
        })
    }

    #[test]
    fn test_user_notification() -> Result<()> {
        let notification = UserNotification::AgentTurnComplete {
            thread_id: "b5f6c1c2-1111-2222-3333-444455556666".to_string(),
            turn_id: "12345".to_string(),
            cwd: test_path_buf("/Users/example/project")
                .display()
                .to_string(),
            client: Some("codex-tui".to_string()),
            input_messages: vec!["Rename `foo` to `bar` and update the callsites.".to_string()],
            last_assistant_message: Some(
                "Rename complete and verified `cargo build` succeeds.".to_string(),
            ),
        };
        let serialized = serde_json::to_string(&notification)?;
        let actual: Value = serde_json::from_str(&serialized)?;
        assert_eq!(actual, expected_notification_json());
        Ok(())
    }

    #[test]
    fn legacy_notify_json_matches_historical_wire_shape() -> Result<()> {
        let payload = HookPayload {
            session_id: ThreadId::new(),
            cwd: test_path_buf("/Users/example/project").abs(),
            client: Some("codex-tui".to_string()),
            triggered_at: chrono::Utc::now(),
            hook_event: HookEvent::AfterAgent {
                event: HookEventAfterAgent {
                    thread_id: ThreadId::from_string("b5f6c1c2-1111-2222-3333-444455556666")
                        .expect("valid thread id"),
                    turn_id: "12345".to_string(),
                    input_messages: vec![
                        "Rename `foo` to `bar` and update the callsites.".to_string(),
                    ],
                    last_assistant_message: Some(
                        "Rename complete and verified `cargo build` succeeds.".to_string(),
                    ),
                },
            },
        };

        let serialized = legacy_notify_json(&payload)?;
        let actual: Value = serde_json::from_str(&serialized)?;
        assert_eq!(actual, expected_notification_json());

        Ok(())
    }

    #[test]
    fn legacy_notify_command_replays_session_snapshot_and_scrubs_credentials() {
        let argv = vec!["notify-command".to_string()];
        let environment = vec![
            (
                OsString::from("CODEX_LEGACY_NOTIFY_SNAPSHOT"),
                OsString::from("captured"),
            ),
            (
                OsString::from(CODEX_EXEC_SERVER_NOISE_AUTH_TOKEN_ENV_VAR),
                OsString::from("restricted-token"),
            ),
        ];

        let command = command_from_argv(&argv, environment)
            .expect("legacy notification command should be configured");
        let configured_environment = command
            .as_std()
            .get_envs()
            .filter_map(|(name, value)| {
                value.map(|value| (name.to_os_string(), value.to_os_string()))
            })
            .collect::<Vec<_>>();

        assert_eq!(
            configured_environment,
            vec![(
                OsString::from("CODEX_LEGACY_NOTIFY_SNAPSHOT"),
                OsString::from("captured"),
            )]
        );
    }

    #[test]
    fn default_argv_transport_keeps_payload_as_final_argument() {
        let payload = "short notification";
        let argv = vec!["notify-helper".to_string(), "--quiet".to_string()];
        let command = notify_command(
            &argv,
            Vec::new(),
            NotifyPayloadTransport::default(),
            Some(payload),
        )
        .expect("command should be configured");
        let args = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(args, vec!["--quiet".to_string(), payload.to_string()]);
    }

    #[test]
    fn stdin_transport_keeps_payload_out_of_args_and_environment() {
        let payload = r#"{"message":"private notification"}"#;
        let argv = vec!["notify-helper".to_string(), "--quiet".to_string()];
        let environment = vec![(
            OsString::from("NOTIFY_TEST_SETTING"),
            OsString::from("enabled"),
        )];
        let command = notify_command(
            &argv,
            environment,
            NotifyPayloadTransport::Stdin,
            Some(payload),
        )
        .expect("command should be configured");
        let std_command = command.as_std();
        let args = std_command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let environment_values = std_command
            .get_envs()
            .filter_map(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(args, vec!["--quiet".to_string()]);
        assert!(
            environment_values
                .iter()
                .all(|value| !value.contains(payload))
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn argv_and_stdin_deliver_identical_legacy_json_to_the_same_fixture() {
        let temp = tempdir().expect("create fixture temp directory");
        let argv = fixture_argv(&temp);
        let payload = notify_payload(
            "Rename `foo` to `bar` and update the callsites.".to_string(),
            "Rename complete and verified `cargo build` succeeds.".to_string(),
        );
        let expected = legacy_notify_json(&payload).expect("serialize notify payload");

        for (transport, mode, file_name) in [
            (NotifyPayloadTransport::default(), "argv", "argv-result"),
            (NotifyPayloadTransport::Stdin, "stdin", "stdin-result"),
        ] {
            let result_path = temp.path().join(file_name);
            let environment = fixture_environment(&temp, mode, &result_path);
            let hook = notify_hook(argv.clone(), environment, transport);
            let response = timeout(Duration::from_secs(5), hook.execute(&payload))
                .await
                .expect("hook delivery should be bounded");

            assert!(matches!(response.result, HookResult::Success));
            assert_fixture_delivery(&result_path, expected.as_bytes()).await;
        }
    }

    #[tokio::test]
    async fn stdin_notify_delivers_large_ascii_payload_exactly() {
        let temp = tempdir().expect("create fixture temp directory");
        let result_path = temp.path().join("large-ascii-result");
        let argv = fixture_argv(&temp);
        let payload = large_ascii_notify_payload();
        let expected = legacy_notify_json(&payload).expect("serialize notify payload");
        assert!(expected.len() > 32_767);
        #[cfg(windows)]
        assert_argv_payload_fails_with_win32_206(&temp, argv.clone(), &payload).await;
        let environment = fixture_environment(&temp, "stdin", &result_path);
        let hook = notify_hook(argv, environment, NotifyPayloadTransport::Stdin);

        let response = timeout(Duration::from_secs(10), hook.execute(&payload))
            .await
            .expect("large hook delivery should be bounded");
        assert!(matches!(response.result, HookResult::Success));
        assert_fixture_delivery(&result_path, expected.as_bytes()).await;
    }

    #[tokio::test]
    async fn stdin_notify_delivers_large_unicode_payload_exactly() {
        let temp = tempdir().expect("create fixture temp directory");
        let result_path = temp.path().join("large-unicode-result");
        let argv = fixture_argv(&temp);
        let payload = large_unicode_notify_payload();
        let expected = legacy_notify_json(&payload).expect("serialize notify payload");
        assert!(expected.encode_utf16().count() > 60_000);
        #[cfg(windows)]
        assert_argv_payload_fails_with_win32_206(&temp, argv.clone(), &payload).await;
        let environment = fixture_environment(&temp, "stdin", &result_path);
        let hook = notify_hook(argv, environment, NotifyPayloadTransport::Stdin);

        let response = timeout(Duration::from_secs(10), hook.execute(&payload))
            .await
            .expect("large hook delivery should be bounded");
        assert!(matches!(response.result, HookResult::Success));
        assert_fixture_delivery(&result_path, expected.as_bytes()).await;
    }

    #[tokio::test]
    async fn missing_notify_executable_returns_error_without_payload() {
        let temp = tempdir().expect("create fixture temp directory");
        let marker = "notify-secret-marker";
        let executable = temp.path().join("missing-helper.exe");
        let hook = notify_hook(
            vec![executable.to_string_lossy().into_owned()],
            Arc::new(Vec::new()),
            NotifyPayloadTransport::Stdin,
        );
        let payload = notify_payload(marker.to_string(), "short answer".to_string());
        let response = hook.execute(&payload).await;

        let HookResult::FailedContinue(error) = response.result else {
            panic!("missing notify executable should fail without aborting");
        };
        assert!(!error.to_string().contains(marker));
    }

    #[tokio::test]
    async fn early_exit_fails_stdin_write_and_reaps_child() {
        let temp = tempdir().expect("create fixture temp directory");
        let result_path = temp.path().join("early-exit-result");
        let environment = fixture_environment(&temp, "exit-before-read", &result_path);
        let argv = fixture_argv(&temp);
        let mut command = notify_command(
            &argv,
            environment.iter().cloned(),
            NotifyPayloadTransport::Stdin,
            Some("not sent on argv"),
        )
        .expect("command should be configured");
        let mut child = command.spawn().expect("start fixture child");
        let started_path = temp.path().join("started");
        let child_pid = String::from_utf8(wait_for_file(&started_path).await)
            .expect("fixture process id should be UTF-8")
            .parse::<u32>()
            .expect("fixture process id should be numeric");

        let marker = "notify-secret-marker";
        let payload = format!("{marker}{}", "x".repeat(2 * 1024 * 1024));
        let error = write_notify_payload(&mut child, payload.as_bytes(), Duration::from_secs(5))
            .await
            .expect_err("closed stdin should fail");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(!error.to_string().contains(marker));

        let status = child
            .try_wait()
            .expect("check child process status")
            .expect("failed write should reap the child");
        assert_eq!(status.code(), Some(17));
        assert!(!process_is_running(child_pid));
    }

    #[tokio::test]
    async fn never_read_timeout_kills_and_reaps_child() {
        let temp = tempdir().expect("create fixture temp directory");
        let result_path = temp.path().join("never-read-result");
        let environment = fixture_environment(&temp, "never-read", &result_path);
        let argv = fixture_argv(&temp);
        let mut command = notify_command(
            &argv,
            environment.iter().cloned(),
            NotifyPayloadTransport::Stdin,
            Some("not sent on argv"),
        )
        .expect("command should be configured");
        let mut child = command.spawn().expect("start fixture child");
        let started_path = temp.path().join("started");
        let child_pid = String::from_utf8(wait_for_file(&started_path).await)
            .expect("fixture process id should be UTF-8")
            .parse::<u32>()
            .expect("fixture process id should be numeric");
        assert!(process_is_running(child_pid));

        let marker = "notify-secret-marker";
        let payload = format!("{marker}{}", "x".repeat(2 * 1024 * 1024));
        let started = Instant::now();
        let error =
            write_notify_payload(&mut child, payload.as_bytes(), Duration::from_millis(100))
                .await
                .expect_err("a child that never reads should time out");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!error.to_string().contains(marker));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            child
                .try_wait()
                .expect("check child process status")
                .is_some(),
            "timed-out write should reap the child"
        );
        assert!(!process_is_running(child_pid));
    }

    #[tokio::test]
    async fn cancelling_blocked_stdin_write_kills_child() {
        let temp = tempdir().expect("create fixture temp directory");
        let result_path = temp.path().join("cancelled-result");
        let started_path = temp.path().join("started");
        let environment = fixture_environment(&temp, "never-read", &result_path);
        let hook = notify_hook(
            fixture_argv(&temp),
            environment,
            NotifyPayloadTransport::Stdin,
        );
        let payload = notify_payload("x".repeat(2 * 1024 * 1024), "short answer".to_string());
        let hook_task = tokio::spawn(async move { hook.execute(&payload).await });

        let child_pid = String::from_utf8(wait_for_file(&started_path).await)
            .expect("fixture process id should be UTF-8")
            .parse::<u32>()
            .expect("fixture process id should be numeric");
        assert!(process_is_running(child_pid));
        sleep(Duration::from_millis(100)).await;
        hook_task.abort();
        assert!(
            hook_task
                .await
                .expect_err("cancelled hook should not complete")
                .is_cancelled()
        );

        wait_for_process_exit(child_pid).await;
        assert!(!result_path.exists());
    }
}
