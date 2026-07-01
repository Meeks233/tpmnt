//! External command execution with structured per-step tracing, dry-run
//! awareness, and a recorded plan. This is the single choke point for every
//! shell-out so that `--dry-run`, `--plan`, and `--debug` are honored uniformly.

use std::cell::RefCell;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::error::{Code, Error, Result};

/// One executed (or planned) external command, captured for `--debug`/`--plan`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Step {
    pub argv: Vec<String>,
    /// Human reason this step exists (shown in --plan).
    pub why: String,
    /// True if this step mutates system state (vs. read-only probe).
    pub destructive: bool,
    /// Populated after execution (None when only planned / dry-run).
    pub exit: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub duration_ms: Option<u128>,
    /// True when dry-run skipped actual execution.
    pub skipped: bool,
}

/// Execution context shared across a command invocation.
pub struct Runner {
    /// When true, destructive steps are recorded but never executed.
    pub dry_run: bool,
    /// When true, emit each step's trace to stderr as line-delimited JSON.
    pub debug: bool,
    /// Recorded steps, in order. Used to build the `--plan` output.
    pub trace: RefCell<Vec<Step>>,
}

impl Runner {
    pub fn new(dry_run: bool, debug: bool) -> Self {
        Runner {
            dry_run,
            debug,
            trace: RefCell::new(Vec::new()),
        }
    }

    fn record(&self, step: Step) {
        if self.debug {
            if let Ok(line) = serde_json::to_string(&step) {
                eprintln!("{line}");
            }
        }
        self.trace.borrow_mut().push(step);
    }

    /// Run a read-only probe. Always executes even under --dry-run, because
    /// probes must reflect reality for planning to be meaningful.
    pub fn probe(&self, argv: &[&str], why: &str) -> Result<Output> {
        self.run_inner(argv, why, false, &[], None)
    }

    /// Run a state-mutating command. Skipped (but recorded) under --dry-run.
    pub fn run(&self, argv: &[&str], why: &str) -> Result<Output> {
        self.run_inner(argv, why, true, &[], None)
    }

    /// Like `probe`, but runs `argv` on a remote by prepending `prefix` (an SSH
    /// argv, e.g. from `Remote::ssh_prefix`). An empty prefix runs locally, so
    /// callers can pass a disk's prefix uniformly. The full wrapped command is
    /// what gets traced, so `--plan` shows the real remote invocation.
    pub fn probe_on(&self, prefix: &[String], argv: &[&str], why: &str) -> Result<Output> {
        let wrapped = wrap(prefix, argv);
        let refs: Vec<&str> = wrapped.iter().map(String::as_str).collect();
        self.run_inner(&refs, why, false, &[], None)
    }

    /// Like `run`, but runs `argv` on a remote by prepending `prefix` (an SSH
    /// argv). An empty prefix runs locally, so callers pass a disk's prefix
    /// uniformly. Skipped (but recorded, as the full wrapped command) under
    /// --dry-run, so `--plan` shows the real remote invocation.
    pub fn run_on(&self, prefix: &[String], argv: &[&str], why: &str) -> Result<Output> {
        let wrapped = wrap(prefix, argv);
        let refs: Vec<&str> = wrapped.iter().map(String::as_str).collect();
        self.run_inner(&refs, why, true, &[], None)
    }

    /// Like `run`, but injects environment variables (e.g. `$PASSWORD` for
    /// systemd-cryptenroll). Env values are NOT recorded in the trace.
    pub fn run_env(&self, argv: &[&str], envs: &[(&str, &str)], why: &str) -> Result<Output> {
        self.run_inner(argv, why, true, envs, None)
    }

    /// Like `run`, but feeds `stdin` to the child (e.g. a secret bundle to
    /// `age`/`gpg`). The stdin bytes are NOT recorded in the trace.
    pub fn run_stdin(&self, argv: &[&str], stdin: &[u8], why: &str) -> Result<Output> {
        self.run_inner(argv, why, true, &[], Some(stdin))
    }

    fn run_inner(
        &self,
        argv: &[&str],
        why: &str,
        destructive: bool,
        envs: &[(&str, &str)],
        stdin: Option<&[u8]>,
    ) -> Result<Output> {
        let argv_owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();

        if destructive && self.dry_run {
            self.record(Step {
                argv: argv_owned,
                why: why.to_string(),
                destructive,
                exit: None,
                stdout: None,
                stderr: None,
                duration_ms: None,
                skipped: true,
            });
            return Ok(Output {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        let start = Instant::now();
        let mut cmd = Command::new(argv[0]);
        cmd.args(&argv[1..]);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let result = if let Some(input) = stdin {
            run_with_stdin(cmd, input)
        } else {
            cmd.output()
        };
        let elapsed = start.elapsed().as_millis();

        match result {
            Ok(out) => {
                let status = out.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
                self.record(Step {
                    argv: argv_owned,
                    why: why.to_string(),
                    destructive,
                    exit: Some(status),
                    stdout: Some(stdout.clone()),
                    stderr: Some(stderr.clone()),
                    duration_ms: Some(elapsed),
                    skipped: false,
                });
                Ok(Output {
                    status,
                    stdout,
                    stderr,
                })
            }
            Err(e) => {
                self.record(Step {
                    argv: argv_owned,
                    why: why.to_string(),
                    destructive,
                    exit: None,
                    stdout: None,
                    stderr: Some(e.to_string()),
                    duration_ms: Some(elapsed),
                    skipped: false,
                });
                if e.kind() == std::io::ErrorKind::NotFound {
                    Err(Error::new(
                        Code::EMissingTool,
                        format!("external tool not found: {}", argv[0]),
                    )
                    .with_hint(format!("install the package providing `{}`", argv[0])))
                } else {
                    Err(Error::new(
                        Code::ECommandFailed,
                        format!("failed to spawn `{}`: {e}", argv[0]),
                    ))
                }
            }
        }
    }
}

/// Prepend a remote `prefix` (SSH argv) to a local `argv`. An empty prefix
/// leaves the command untouched (local execution). The remote command is passed
/// as a single trailing string so the remote shell re-parses it, matching how
/// `ssh host cmd arg…` already collapses its trailing words.
fn wrap(prefix: &[String], argv: &[&str]) -> Vec<String> {
    if prefix.is_empty() {
        return argv.iter().map(|s| s.to_string()).collect();
    }
    let mut out: Vec<String> = prefix.to_vec();
    out.extend(argv.iter().map(|s| s.to_string()));
    out
}

/// Spawn `cmd` with a piped stdin, write `input`, and collect output.
fn run_with_stdin(mut cmd: Command, input: &[u8]) -> std::io::Result<std::process::Output> {
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let Some(mut sin) = child.stdin.take() {
        sin.write_all(input)?;
        // Drop closes stdin so the child sees EOF.
    }
    child.wait_with_output()
}

/// Result of running a command.
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    /// Require success or convert to a structured ECommandFailed error.
    pub fn require(self, context: &str) -> Result<Output> {
        if self.ok() {
            Ok(self)
        } else {
            Err(Error::new(
                Code::ECommandFailed,
                format!("{context} (exit {})", self.status),
            )
            .with_hint(self.stderr.trim().to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wrap;

    #[test]
    fn wrap_empty_prefix_is_local() {
        assert_eq!(
            wrap(&[], &["cryptsetup", "luksDump", "/dev/x"]),
            vec!["cryptsetup".to_string(), "luksDump".into(), "/dev/x".into()]
        );
    }

    #[test]
    fn wrap_prepends_ssh_prefix() {
        let prefix = vec!["ssh".to_string(), "alice@host".into()];
        assert_eq!(
            wrap(&prefix, &["test", "-e", "/dev/mapper/m"]),
            vec![
                "ssh".to_string(),
                "alice@host".into(),
                "test".into(),
                "-e".into(),
                "/dev/mapper/m".into()
            ]
        );
    }
}
