//! Apply Patch runtime: executes verified patches under the orchestrator.
//!
//! Assumes `apply_patch` verification/approval happened upstream. Reuses that
//! decision to avoid re-prompting, builds the self-invocation command for
//! `codex --codex-run-as-apply-patch`, and runs under the current
//! `SandboxAttempt` with a minimal environment.
use crate::CODEX_APPLY_PATCH_ARG1;
use crate::exec::ExecToolCallOutput;
use crate::sandboxing::CommandSpec;
use crate::sandboxing::execute_env;
use crate::tools::sandboxing::Approvable;
use crate::tools::sandboxing::ApprovalCtx;
use crate::tools::sandboxing::SandboxAttempt;
use crate::tools::sandboxing::Sandboxable;
use crate::tools::sandboxing::SandboxablePreference;
use crate::tools::sandboxing::ToolCtx;
use crate::tools::sandboxing::ToolError;
use crate::tools::sandboxing::ToolRuntime;
use crate::tools::sandboxing::with_cached_approval;
use codex_protocol::protocol::ReviewDecision;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ApplyPatchRequest {
    pub patch: String,
    pub cwd: PathBuf,
    pub timeout_ms: Option<u64>,
    pub user_explicitly_approved: bool,
    pub codex_exe: Option<PathBuf>,
}

#[derive(Default)]
pub struct ApplyPatchRuntime;

#[derive(serde::Serialize, Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct ApprovalKey {
    patch: String,
    cwd: PathBuf,
}

impl ApplyPatchRuntime {
    pub fn new() -> Self {
        Self
    }

    fn build_command_spec(req: &ApplyPatchRequest) -> Result<CommandSpec, ToolError> {
        use std::env;
        let exe = if let Some(path) = &req.codex_exe {
            path.clone()
        } else {
            env::current_exe()
                .map_err(|e| ToolError::Rejected(format!("failed to determine codex exe: {e}")))?
        };
        let program = exe.to_string_lossy().to_string();
        Ok(CommandSpec {
            program,
            args: vec![CODEX_APPLY_PATCH_ARG1.to_string(), req.patch.clone()],
            cwd: req.cwd.clone(),
            timeout_ms: req.timeout_ms,
            // Run apply_patch with a minimal environment for determinism and to avoid leaks.
            env: HashMap::new(),
            with_escalated_permissions: None,
            justification: None,
        })
    }

    fn stdout_stream(ctx: &ToolCtx<'_>) -> Option<crate::exec::StdoutStream> {
        Some(crate::exec::StdoutStream {
            sub_id: ctx.sub_id.clone(),
            call_id: ctx.call_id.clone(),
            tx_event: ctx.session.get_tx_event(),
        })
    }
}

impl Sandboxable for ApplyPatchRuntime {
    fn sandbox_preference(&self) -> SandboxablePreference {
        SandboxablePreference::Auto
    }
    fn escalate_on_failure(&self) -> bool {
        true
    }
}

impl Approvable<ApplyPatchRequest> for ApplyPatchRuntime {
    type ApprovalKey = ApprovalKey;

    fn approval_key(&self, req: &ApplyPatchRequest) -> Self::ApprovalKey {
        ApprovalKey {
            patch: req.patch.clone(),
            cwd: req.cwd.clone(),
        }
    }

    fn start_approval_async<'a>(
        &'a mut self,
        req: &'a ApplyPatchRequest,
        ctx: ApprovalCtx<'a>,
    ) -> BoxFuture<'a, ReviewDecision> {
        let key = self.approval_key(req);
        let session = ctx.session;
        let sub_id = ctx.sub_id.to_string();
        let call_id = ctx.call_id.to_string();
        let cwd = req.cwd.clone();
        let retry_reason = ctx.retry_reason.clone();
        let user_explicitly_approved = req.user_explicitly_approved;
        Box::pin(async move {
            with_cached_approval(&session.services, key, || async move {
                if let Some(reason) = retry_reason {
                    session
                        .request_command_approval(
                            sub_id,
                            call_id,
                            vec!["apply_patch".to_string()],
                            cwd,
                            Some(reason),
                        )
                        .await
                } else if user_explicitly_approved {
                    ReviewDecision::ApprovedForSession
                } else {
                    ReviewDecision::Approved
                }
            })
            .await
        })
    }

    fn wants_escalated_first_attempt(&self, req: &ApplyPatchRequest) -> bool {
        req.user_explicitly_approved
    }
}

impl ToolRuntime<ApplyPatchRequest, ExecToolCallOutput> for ApplyPatchRuntime {
    async fn run(
        &mut self,
        req: &ApplyPatchRequest,
        attempt: &SandboxAttempt<'_>,
        ctx: &ToolCtx<'_>,
    ) -> Result<ExecToolCallOutput, ToolError> {
        if req.user_explicitly_approved {
            return run_apply_patch_in_process(req);
        }

        let spec = Self::build_command_spec(req)?;
        let env = attempt
            .env_for(&spec)
            .map_err(|err| ToolError::Codex(err.into()))?;
        let out = execute_env(&env, attempt.policy, Self::stdout_stream(ctx))
            .await
            .map_err(ToolError::Codex)?;
        Ok(out)
    }
}

fn run_apply_patch_in_process(req: &ApplyPatchRequest) -> Result<ExecToolCallOutput, ToolError> {
    static APPLY_PATCH_CWD_GUARD: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    let _lock = APPLY_PATCH_CWD_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let cwd_guard = WorkingDirGuard::change_to(&req.cwd).map_err(|err| {
        ToolError::Rejected(format!("failed to change to {}: {err}", req.cwd.display()))
    })?;

    let mut out_buf: Vec<u8> = Vec::new();
    let mut err_buf: Vec<u8> = Vec::new();
    let result = codex_apply_patch::apply_patch(&req.patch, &mut out_buf, &mut err_buf);
    drop(cwd_guard);

    let exit_code = if result.is_ok() { 0 } else { 1 };
    let stdout_text = String::from_utf8_lossy(&out_buf).to_string();
    let stderr_text = String::from_utf8_lossy(&err_buf).to_string();
    let aggregated = if stdout_text.is_empty() {
        stderr_text.clone()
    } else if stderr_text.is_empty() {
        stdout_text.clone()
    } else {
        format!("{stdout_text}\n{stderr_text}")
    };

    Ok(ExecToolCallOutput {
        exit_code,
        stdout: crate::exec::StreamOutput::new(stdout_text),
        stderr: crate::exec::StreamOutput::new(stderr_text),
        aggregated_output: crate::exec::StreamOutput::new(aggregated),
        duration: Duration::default(),
        timed_out: false,
    })
}

struct WorkingDirGuard {
    original: PathBuf,
}

impl WorkingDirGuard {
    fn change_to(path: &Path) -> std::io::Result<Self> {
        let original = std::env::current_dir()?;
        std::env::set_current_dir(path)?;
        Ok(Self { original })
    }
}

impl Drop for WorkingDirGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}
