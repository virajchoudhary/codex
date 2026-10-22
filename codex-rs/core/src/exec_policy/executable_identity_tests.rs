use super::shell_approval_command;
use crate::exec_policy::AllowPrefixRules;
use crate::exec_policy::ExecApprovalRequest;
use crate::exec_policy::ExecPolicyManager;
use crate::sandboxing::SandboxPermissions;
use crate::shell::Shell;
use crate::shell::ShellType;
use crate::tools::sandboxing::ExecApprovalRequirement;
use codex_execpolicy::Policy;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::PermissionProfile;
use codex_protocol::protocol::AskForApproval;
use codex_shell_command::is_dangerous_command::DangerousCommandPlatform;
use pretty_assertions::assert_eq;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::test]
async fn unfamiliar_powershell_opaque_scripts_keep_wrapper_heuristics() {
    let shell = Shell {
        shell_type: ShellType::PowerShell,
        shell_path: PathBuf::from("other-shell"),
    };
    for script in [
        "$p = [System.Diagnostics.ProcessStartInfo]::new(); $p.UseShellExecute = $false; $p.Arguments = 'https://example.com'; $p.UseShellExecute",
        "$p.UseShellExecute=$false; $p.FileName='https://example.com'; [Diagnostics.Process]::Start($p)",
    ] {
        let command = vec![
            "pwsh".to_string(),
            "-Command".to_string(),
            script.to_string(),
        ];
        for approval_policy in [AskForApproval::Never, AskForApproval::OnRequest] {
            let manager = ExecPolicyManager::new(Arc::new(Policy::empty()));
            let requirement = manager
                .create_exec_approval_requirement_for_shell(
                    ExecApprovalRequest {
                        command: &command,
                        approval_policy,
                        permission_profile: PermissionProfile::Disabled,
                        environment_policy: None,
                        windows_sandbox_level: WindowsSandboxLevel::Disabled,
                        sandbox_permissions: SandboxPermissions::UseDefault,
                        prefix_rule: None,
                        allow_prefix_rules: AllowPrefixRules::Honor,
                    },
                    &shell,
                    DangerousCommandPlatform::Windows,
                )
                .await;
            assert!(
                if approval_policy == AskForApproval::Never {
                    matches!(requirement, ExecApprovalRequirement::Forbidden { .. })
                } else {
                    matches!(requirement, ExecApprovalRequirement::NeedsApproval { .. })
                },
                "{command:?}; {approval_policy:?}; {requirement:?}"
            );
        }
    }
}

#[test]
fn parent_directory_traversal_is_not_a_trusted_system_shell() {
    let (configured_executable, unfamiliar_executable) = if cfg!(windows) {
        let system_root = std::env::var_os("SystemRoot").expect("Windows SystemRoot");
        let system_directory = PathBuf::from(system_root).join("System32");
        (
            system_directory.join("cmd.exe"),
            system_directory
                .join("..")
                .join("workspace")
                .join("powershell.exe"),
        )
    } else {
        (
            PathBuf::from("/bin/sh"),
            PathBuf::from("/bin/../workspace/bash"),
        )
    };
    let shell = Shell {
        shell_type: if cfg!(windows) {
            ShellType::Cmd
        } else {
            ShellType::Sh
        },
        shell_path: configured_executable,
    };
    let command = vec![
        unfamiliar_executable.to_string_lossy().into_owned(),
        "-c".to_string(),
        "ls".to_string(),
    ];

    assert_eq!(shell_approval_command(&command, &shell), &command[..1],);
}

#[cfg(windows)]
#[test]
fn windows_shell_identity_is_case_insensitive() {
    let configured_executable = PathBuf::from(r"C:\Custom\pwsh.exe");
    let configured_shell = Shell {
        shell_type: ShellType::PowerShell,
        shell_path: configured_executable.clone(),
    };
    let system_root = std::env::var_os("SystemRoot").expect("Windows SystemRoot");
    let system_executable = PathBuf::from(system_root.to_string_lossy().to_ascii_uppercase())
        .join("SYSTEM32")
        .join("WINDOWSPOWERSHELL")
        .join("V1.0")
        .join("POWERSHELL.EXE");

    for executable in [
        configured_executable.to_string_lossy().to_ascii_uppercase(),
        system_executable.to_string_lossy().into_owned(),
    ] {
        let command = vec![executable, "-Command".to_string(), "echo safe".to_string()];

        assert_eq!(
            shell_approval_command(&command, &configured_shell),
            command.as_slice(),
        );
    }
}
