// CoreELEC ARM32 userspace compatibility for Codex 0.163.0.
// Keep seccompiler's native AArch64 filter intact and compile its existing
// rule/argument conditions again for the ARM EABI syscall numbers.
use seccompiler::{
    BackendError, BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch, sock_filter,
};
use std::collections::BTreeMap;

const AUDIT_ARCH_ARM: u32 = 0x40000028;
const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;

fn arm_syscall(aarch64: i64) -> i64 {
    // Linux arch/arm/include/uapi/asm/unistd.h and asm-generic/unistd.h.
    // An upstream rule addition without a mapping must fail closed.
    match aarch64 {
        117 => 26,            // ptrace
        270 => 376,           // process_vm_readv
        271 => 377,           // process_vm_writev
        425..=427 => aarch64, // io_uring_{setup,enter,register}
        203 => 283,           // connect
        202 => 285,           // accept
        242 => 366,           // accept4
        200 => 282,           // bind
        201 => 284,           // listen
        205 => 287,           // getpeername
        204 => 286,           // getsockname
        210 => 293,           // shutdown
        206 => 290,           // sendto
        269 => 374,           // sendmmsg
        243 => 365,           // recvmmsg
        209 => 295,           // getsockopt
        208 => 294,           // setsockopt
        198 => 281,           // socket
        199 => 288,           // socketpair
        _ => panic!("Codex sandbox syscall {aarch64} has no ARM32 policy mapping"),
    }
}

pub(super) fn with_arm_compat(
    native: BpfProgram,
    rules: BTreeMap<i64, Vec<SeccompRule>>,
) -> Result<BpfProgram, BackendError> {
    let mut arm_rules: BTreeMap<_, _> = rules
        .into_iter()
        .map(|(number, conditions)| (arm_syscall(number), conditions))
        .collect();
    // Do not allow an alternate socket ABI to evade the socket rules.
    arm_rules.insert(102, vec![]); // legacy socketcall
    let mut compat: BpfProgram = SeccompFilter::new(
        arm_rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        TargetArch::aarch64,
    )?
    .try_into()?;
    // seccompiler 0.5.0 lacks TargetArch::arm. Only retarget its architecture
    // guard; leave all generated syscall and argument checks unchanged.
    assert_eq!(compat[0].code, 0x20);
    assert_eq!(compat[0].k, 4);
    assert_eq!(compat[1].code, 0x15);
    assert_eq!(compat[1].k, AUDIT_ARCH_AARCH64);
    compat[1].k = AUDIT_ARCH_ARM;
    let mut program = vec![
        sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 4,
        }, // load arch
        sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_ARM,
        },
        sock_filter {
            code: 0x05,
            jt: 0,
            jf: 0,
            k: compat.len() as u32,
        },
    ];
    program.extend(compat);
    // Every other ABI still reaches the unmodified native architecture guard.
    program.extend(native);
    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition};

    fn evaluate(program: &BpfProgram, arch: u32, nr: u32, argument: u64) -> u32 {
        let mut pc = 0usize;
        let mut accumulator = 0u32;
        for _ in 0..4096 {
            let instruction = &program[pc];
            match instruction.code {
                0x20 => {
                    accumulator = match instruction.k {
                        0 => nr,
                        4 => arch,
                        16 => argument as u32,
                        20 => (argument >> 32) as u32,
                        _ => panic!("unexpected BPF load"),
                    }
                }
                0x05 => {
                    pc += instruction.k as usize + 1;
                    continue;
                }
                0x15 | 0x25 | 0x35 | 0x45 => {
                    let yes = match instruction.code {
                        0x15 => accumulator == instruction.k,
                        0x25 => accumulator > instruction.k,
                        0x35 => accumulator >= instruction.k,
                        _ => accumulator & instruction.k != 0,
                    };
                    pc += usize::from(if yes { instruction.jt } else { instruction.jf }) + 1;
                    continue;
                }
                0x54 => accumulator &= instruction.k,
                0x06 => return instruction.k,
                _ => panic!("unexpected BPF operation {}", instruction.code),
            }
            pc += 1;
        }
        panic!("BPF did not terminate")
    }

    fn compile(rules: BTreeMap<i64, Vec<SeccompRule>>) -> BpfProgram {
        let native = SeccompFilter::new(
            rules.clone(),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            TargetArch::aarch64,
        )
        .unwrap()
        .try_into()
        .unwrap();
        with_arm_compat(native, rules).unwrap()
    }

    #[test]
    fn equivalent_network_and_memory_restrictions_for_both_abis() {
        let unix_only = SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                libc::AF_UNIX as u64,
            )
            .unwrap(),
        ])
        .unwrap();
        let program = compile(BTreeMap::from([
            (117, vec![]),
            (270, vec![]),
            (271, vec![]),
            (203, vec![]),
            (198, vec![unix_only.clone()]),
            (199, vec![unix_only]),
        ]));
        let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        for (arch, socket, socketpair, memory, write_memory, ptrace, connect, getpid) in [
            (AUDIT_ARCH_AARCH64, 198, 199, 270, 271, 117, 203, 172),
            (AUDIT_ARCH_ARM, 281, 288, 376, 377, 26, 283, 20),
        ] {
            for nr in [socket, socketpair] {
                assert_eq!(
                    evaluate(&program, arch, nr, libc::AF_UNIX as u64),
                    libc::SECCOMP_RET_ALLOW
                );
                for family in [libc::AF_INET, libc::AF_INET6, libc::AF_VSOCK] {
                    assert_eq!(evaluate(&program, arch, nr, family as u64), deny);
                }
            }
            for nr in [memory, write_memory, ptrace, connect] {
                assert_eq!(evaluate(&program, arch, nr, 0), deny);
            }
            assert_eq!(evaluate(&program, arch, getpid, 0), libc::SECCOMP_RET_ALLOW);
        }
        assert_eq!(evaluate(&program, AUDIT_ARCH_ARM, 102, 0), deny);
        for unknown in [0, 0x40000003, 0xc000003e] {
            assert_eq!(
                evaluate(&program, unknown, 20, 0),
                libc::SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn vm_socket_rule_preserves_ordinary_network_access_for_both_abis() {
        let rule = SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_VSOCK as u64,
            )
            .unwrap(),
        ])
        .unwrap();
        let program = compile(BTreeMap::from([
            (198, vec![rule.clone()]),
            (199, vec![rule]),
        ]));
        for (arch, numbers) in [
            (AUDIT_ARCH_AARCH64, [198, 199]),
            (AUDIT_ARCH_ARM, [281, 288]),
        ] {
            for number in numbers {
                assert_eq!(
                    evaluate(&program, arch, number, libc::AF_VSOCK as u64),
                    libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
                );
                for family in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX] {
                    assert_eq!(
                        evaluate(&program, arch, number, family as u64),
                        libc::SECCOMP_RET_ALLOW
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "has no ARM32 policy mapping")]
    fn upstream_rule_additions_cannot_silently_lose_compat_enforcement() {
        compile(BTreeMap::from([(123456, vec![])]));
    }
}
