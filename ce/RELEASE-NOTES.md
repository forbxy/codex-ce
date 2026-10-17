CoreELEC compatibility build based on upstream Codex 0.163.0.

- Preserve the upstream AArch64 seccomp program and apply equivalent syscall restrictions to ARM EABI children.
- Recognize CoreELEC 4.9's proc-mount EBUSY error and use the existing upstream compatibility fallback.
- Preserve filesystem protection, approval handling, and bundled bwrap SHA256 verification.
- Bundle the unmodified upstream bwrap and code-mode-host from the same release.

This is a third-party compatibility prerelease, not an official OpenAI release.
The earlier local trial passed 13 offline boundary checks and a live automatic-approval check on CoreELEC NG (ARM64 kernel with ARM32 userspace).
CI runs the BPF semantic unit tests and release checks; CI does not replace physical CoreELEC validation or test manual approval UI.
See `ce/README.md` for build, device verification, and upgrade instructions.
