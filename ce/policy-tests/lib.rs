//! Host-native tests of the production ARM32/AArch64 BPF generator.
#![allow(dead_code)]

#[path = "../../codex-rs/linux-sandbox/src/seccomp_arm_compat.rs"]
mod arm_compat;

include!(concat!(env!("OUT_DIR"), "/proc_failure.rs"));

#[test]
fn proc_fallback_recognizes_only_known_proc_mount_failures() {
    for reason in [
        "Resource busy",
        "Invalid argument",
        "Operation not permitted",
        "Permission denied",
    ] {
        assert!(is_proc_mount_failure(&format!(
            "bwrap: Can't mount proc on /newroot/proc: {reason}"
        )));
    }
    for unrelated in [
        "bwrap: Can't mount /storage: Resource busy",
        "bwrap: Can't mount proc on /newroot/other: Resource busy",
        "bwrap: Can't mount proc on /newroot/proc: Input/output error",
    ] {
        assert!(!is_proc_mount_failure(unrelated));
    }
}
