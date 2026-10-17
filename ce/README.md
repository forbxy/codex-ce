# Codex for CoreELEC

This fork maintains a small compatibility patch on top of the official Codex release.
The current branch is based on `rust-v0.163.0`. It targets an ARM64 Linux kernel with ARM32 CoreELEC NG userspace; other branches/devices need their own validation.

## Changes

1. Treat `/newroot/proc` mount failures reporting `Resource busy` as the existing upstream proc compatibility case. Other mount failures remain errors.
2. Keep the original AArch64 seccomp program unchanged, compile the same rules and argument conditions for ARM EABI syscall numbers, and dispatch by architecture. Unknown architectures remain rejected. New upstream syscall rules without ARM mappings fail closed.
3. Normalize only local workspace package versions in the release tag's Cargo.lock. External dependency records remain identical to upstream.

No model, login, approval, or agent logic is changed. The default sandbox remains enabled. The bundle includes the original official bwrap and code-mode-host of the matching upstream release. The bwrap executable digest is checked by Codex at runtime.

## Build

On Linux x86_64, install Git, Python 3.12+, a C/C++ build toolchain, pkg-config, Perl, CMake, and Ninja. Then run:

```sh
python3 ce/build.py build
```

The script downloads checksum-pinned Rustup and Zig into `.cache/ce`, installs the pinned Rust toolchain locally, tests the ARM BPF generator on the host, and cross-compiles the checked-out app-server for `aarch64-unknown-linux-musl` using Zig. It never installs a global toolchain or reads a Codex account.

`--cache PATH` reuses an existing build cache; `--jobs N` controls build parallelism. Commit source changes before packaging: release provenance rejects tracked dirty source.

Artifacts are written to `dist/ce/`: one component archive, `component.json` for the Kodi addon download catalog, `build-info.json`, the sandbox patch, SHA256SUMS, and MD5SUMS. The archive contains app-server, code-mode-host, `codex-resources/bwrap`, provenance and license notices. Preserve the upstream LICENSE/NOTICE and the bwrap license. Corresponding upstream and modified source are available in this repository/tag.

`CODEX_BWRAP_SHA256` is the SHA256 of the extracted bwrap executable, not its compressed archive. It must remain enabled.

## Device validation

Copy the archive and `ce/test_on_ce.py` to a disposable directory under `/storage/.cache`, extract the archive there, and run:

```sh
python3 test_on_ce.py --bundle /storage/.cache/codex-ce-test/bundle --output /storage/.cache/codex-ce-test/report.json
```

The test makes another private temporary copy before testing tamper detection. It does not read account files, open a microphone, contact a model, or change Kodi settings. It checks ARM32 shell/Python, ARM64 execution, filesystem boundaries, symlinks, networking and process-memory restrictions, host proc access, and bwrap digest enforcement. Then validate automatic/manual approvals and the addon's real resident connection separately with a configured account.

The prior trial passed 13 offline boundary checks, automatic approval after sandbox denial, and the addon's real resident connection. Manual approval UI has not yet been separately retested.

## Releases and upgrades

Keep `main` aligned with upstream. Maintain compatibility on `ce/<upstream-version>` branches. GitHub Actions builds CE branch changes and publishes a prerelease when a matching `ce-v*` tag is pushed. The release tag must equal `ce/build-config.json`.

For an upstream upgrade, start a new branch from its official tag and cherry-pick only the CE commits. Review every changed seccomp syscall and argument rule; update ARM EABI mappings rather than removing fail-closed checks. Update the pinned versions, input hashes and release tag, run host tests and real CoreELEC checks, and publish a new immutable tag. Do not overwrite an old tag or release asset. Pin the addon to that release's `component.json` only after verification.

This is an independent CoreELEC compatibility build, not an official OpenAI release.
