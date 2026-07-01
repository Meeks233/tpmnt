//! Stable, machine-readable error taxonomy. Every failure path maps to a
//! documented code so AI agents and scripts can branch on it deterministically.

use std::fmt;

/// Stable error codes. These are part of the CLI contract: do not rename or
/// repurpose. New variants may be appended. The shared `E` prefix mirrors the
/// documented machine codes (E_NOT_LUKS2, …), so the lint is intentional here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Code {
    /// Generic/uncategorized internal failure.
    EInternal,
    /// Config file missing, unreadable, or invalid TOML.
    EConfig,
    /// A required external tool is not installed / not on PATH.
    EMissingTool,
    /// The target device does not exist or is not a block device/file.
    ENoDevice,
    /// The device is not a LUKS2 container (e.g. LUKS1 or plain).
    ENotLuks2,
    /// No TPM2 device available (/dev/tpmrm0 absent and no override).
    ENoTpm,
    /// Refusing to proceed because no non-TPM fallback keyslot exists.
    ENoFallbackKeyslot,
    /// A required passphrase was not provided.
    ENoPassphrase,
    /// An external command exited non-zero.
    ECommandFailed,
    /// No rollback backup is available for the requested device.
    ENoBackup,
    /// `init` refused to touch a device that already has data/partitions.
    EDeviceHasData,
    /// A key-escrow target could not be written/verified.
    EEscrowFailed,
    /// `init` refused to finish because the key bundle was not backed up.
    EBackupRefused,
    /// A jump/bastion host was unreachable during reachability checks.
    EJumpUnreachable,
    /// The final remote target was unreachable.
    ETargetUnreachable,
    /// The remote sshd has no usable sftp path (subsystem nor direct-exec).
    ESftpUnavailable,
    /// The mountpoint is already a mountpoint / busy.
    EMountpointBusy,
    /// The configured SSH identity file is missing.
    EIdentityMissing,
    /// A disk power-down command (hdparm/udisksctl) failed.
    EPowerOff,
    /// A destructive lifecycle op (e.g. `destroy`) was invoked without the
    /// required explicit confirmation.
    EConfirmationRequired,
    /// Forwarding a remote disk's ciphertext block device failed (NBD/NVMe-TCP
    /// attach, tunnel, or missing remote).
    ETransport,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::EInternal => "E_INTERNAL",
            Code::EConfig => "E_CONFIG",
            Code::EMissingTool => "E_MISSING_TOOL",
            Code::ENoDevice => "E_NO_DEVICE",
            Code::ENotLuks2 => "E_NOT_LUKS2",
            Code::ENoTpm => "E_NO_TPM",
            Code::ENoFallbackKeyslot => "E_NO_FALLBACK_KEYSLOT",
            Code::ENoPassphrase => "E_NO_PASSPHRASE",
            Code::ECommandFailed => "E_COMMAND_FAILED",
            Code::ENoBackup => "E_NO_BACKUP",
            Code::EDeviceHasData => "E_DEVICE_HAS_DATA",
            Code::EEscrowFailed => "E_ESCROW_FAILED",
            Code::EBackupRefused => "E_BACKUP_REFUSED",
            Code::EJumpUnreachable => "E_JUMP_UNREACHABLE",
            Code::ETargetUnreachable => "E_TARGET_UNREACHABLE",
            Code::ESftpUnavailable => "E_SFTP_UNAVAILABLE",
            Code::EMountpointBusy => "E_MOUNTPOINT_BUSY",
            Code::EIdentityMissing => "E_IDENTITY_MISSING",
            Code::EPowerOff => "E_POWER_OFF",
            Code::EConfirmationRequired => "E_CONFIRMATION_REQUIRED",
            Code::ETransport => "E_TRANSPORT",
        }
    }

    /// Process exit code associated with this error class.
    pub fn exit_code(self) -> i32 {
        match self {
            Code::EInternal => 1,
            Code::EConfig => 2,
            Code::EMissingTool => 3,
            Code::ENoDevice => 4,
            Code::ENotLuks2 => 5,
            Code::ENoTpm => 6,
            Code::ENoFallbackKeyslot => 7,
            Code::ENoPassphrase => 8,
            Code::ECommandFailed => 9,
            Code::ENoBackup => 11,
            Code::EDeviceHasData => 12,
            Code::EEscrowFailed => 13,
            Code::EBackupRefused => 14,
            Code::EJumpUnreachable => 15,
            Code::ETargetUnreachable => 16,
            Code::ESftpUnavailable => 17,
            Code::EMountpointBusy => 18,
            Code::EIdentityMissing => 19,
            Code::EPowerOff => 20,
            Code::EConfirmationRequired => 21,
            Code::ETransport => 22,
        }
    }
}

/// A structured error carrying a stable code, a human message, and an optional
/// remediation hint. Serializes to the documented JSON error object.
#[derive(Debug)]
pub struct Error {
    pub code: Code,
    pub message: String,
    pub hint: Option<String>,
}

impl Error {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Render the documented machine-readable JSON error object.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "error": {
                "code": self.code.as_str(),
                "message": self.message,
                "hint": self.hint,
            }
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code.as_str(), self.message)?;
        if let Some(h) = &self.hint {
            write!(f, "\n  hint: {h}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Convenience constructors.
pub fn err<T>(code: Code, message: impl Into<String>) -> Result<T> {
    Err(Error::new(code, message))
}
