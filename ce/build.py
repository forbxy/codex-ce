#!/usr/bin/env python3
"""Build the checked-out CE fork with pinned, workspace-local toolchains."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import struct
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / 'ce/build-config.json').read_text())
PATCH_FILES = ('linux_run_main.rs', 'seccomp.rs', 'seccomp_arm_compat.rs')


def digest(path, algorithm='sha256'):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def run(arguments, **kwargs):
    return subprocess.run(list(map(str, arguments)), check=True, **kwargs)


def git(*arguments):
    return subprocess.check_output(['git', *arguments], cwd=ROOT, text=True).strip()


def download(url, expected, directory):
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / url.rsplit('/', 1)[-1]
    if target.is_file() and digest(target) == expected:
        return target
    temporary = target.with_suffix(target.suffix + '.partial')
    request = urllib.request.Request(url, headers={'User-Agent': 'codex-ce-build/1'})
    with urllib.request.urlopen(request, timeout=180) as source, temporary.open('wb') as output:
        shutil.copyfileobj(source, output)
    if digest(temporary) != expected:
        temporary.unlink()
        raise RuntimeError('Download checksum mismatch: ' + target.name)
    temporary.replace(target)
    return target


def environment(cache, jobs):
    env = os.environ.copy()
    env.update(RUSTUP_HOME=str(cache / 'rustup'), CARGO_HOME=str(cache / 'cargo'),
        RUSTUP_TOOLCHAIN=CONFIG['rust'], PATH=str(cache / 'cargo/bin') + ':' + env['PATH'],
        CARGO_TARGET_DIR=str(cache / 'target'), CARGO_BUILD_JOBS=str(jobs),
        CARGO_NET_GIT_FETCH_WITH_CLI='true', CARGO_HTTP_TIMEOUT='120')
    return env


def bootstrap(cache, env):
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        raise RuntimeError('This recipe cross-compiles on Linux x86_64 for Linux AArch64.')
    downloads = cache / 'downloads'
    rustup = cache / 'cargo/bin/rustup'
    if not rustup.exists():
        installer = download(CONFIG['rustup']['url'], CONFIG['rustup']['sha256'], downloads)
        installer.chmod(0o755)
        run([installer, '-y', '--no-modify-path', '--default-toolchain', 'none'], env=env)
    target_lib = cache / 'rustup/toolchains' / (CONFIG['rust'] + '-x86_64-unknown-linux-gnu') / 'lib/rustlib' / CONFIG['target'] / 'lib'
    rustfmt = target_lib.parents[3] / 'bin/rustfmt'
    if not target_lib.is_dir() or not rustfmt.exists():
        run([rustup, 'toolchain', 'install', CONFIG['rust'], '--profile', 'minimal',
             '--component', 'rustfmt', '--target', CONFIG['target']], env=env)
    zig = cache / 'zig/zig'
    if not zig.exists():
        archive = download(CONFIG['zig']['url'], CONFIG['zig']['sha256'], downloads)
        staging = cache / 'zig-unpack'
        staging.mkdir(exist_ok=True)
        with tarfile.open(archive) as stream:
            stream.extractall(staging, filter='data')
        directories = [p for p in staging.iterdir() if p.is_dir()]
        if len(directories) != 1:
            raise RuntimeError('Unexpected Zig archive layout')
        directories[0].rename(cache / 'zig')
        staging.rmdir()
    if subprocess.check_output([zig, 'version'], text=True).strip() != CONFIG['zig']['version']:
        raise RuntimeError('Unexpected Zig version')


def cross_environment(cache, env):
    wrappers = cache / 'bin'
    wrappers.mkdir(parents=True, exist_ok=True)
    for name, args in [('zig-cc', ['cc', '-target', 'aarch64-linux-musl']),
                       ('zig-cxx', ['c++', '-target', 'aarch64-linux-musl']), ('zig-ar', ['ar'])]:
        path = wrappers / name
        if name == 'zig-ar':
            path.write_text('#!/bin/sh\nexec ' + shlex.join([str(cache / 'zig/zig'), *args]) + ' "$@"\n')
        else:
            path.write_text('#!/usr/bin/python3\nimport os,sys\n'
                'args=[a for a in sys.argv[1:] if not a.startswith("--target=")]\n'
                'os.execv(' + repr(str(cache / 'zig/zig')) + ', ' +
                repr([str(cache / 'zig/zig'), *args]) + '+args)\n')
        path.chmod(0o755)
    result = dict(env)
    result.update(CARGO_PROFILE_RELEASE_LTO='false', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_STRIP='symbols', CARGO_PROFILE_RELEASE_CODEGEN_UNITS='16',
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=str(wrappers / 'zig-cc'),
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS='-C link-self-contained=no',
        CC_aarch64_unknown_linux_musl=str(wrappers / 'zig-cc'),
        CXX_aarch64_unknown_linux_musl=str(wrappers / 'zig-cxx'),
        AR_aarch64_unknown_linux_musl=str(wrappers / 'zig-ar'),
        ZIG_GLOBAL_CACHE_DIR=str(cache / 'zig-cache'), ZIG_LOCAL_CACHE_DIR=str(cache / 'zig-local'),
        CODEX_SKIP_BWRAP_BUILD='1', CODEX_BWRAP_SHA256=CONFIG['bwrap']['binary_sha256'],
        OPENSSL_STATIC='1')
    return result


def test(cache, env):
    # Small host-native harness exercises the exact production ARM BPF generator.
    test_env = dict(env, CARGO_TARGET_DIR=str(cache / 'unit-target'))
    run([cache / 'cargo/bin/cargo', 'test', '--locked', '--manifest-path',
         ROOT / 'ce/policy-tests/Cargo.toml'], cwd=ROOT, env=test_env)
    run([cache / 'cargo/bin/rustfmt', '--edition', '2024', '--check',
         ROOT / 'codex-rs/linux-sandbox/src/seccomp_arm_compat.rs'], env=env)
    run(['python3', '-m', 'unittest', 'discover', '-s', ROOT / 'ce/tests', '-v'], cwd=ROOT)


def static_aarch64(path):
    with path.open('rb') as stream:
        header = stream.read(64)
        if header[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', header, 18)[0] != 183:
            raise RuntimeError('Expected a little-endian ELF64 AArch64 binary')
        offset = struct.unpack_from('<Q', header, 32)[0]
        entry_size, count = struct.unpack_from('<HH', header, 54)
        for index in range(count):
            stream.seek(offset + index * entry_size)
            if struct.unpack('<I', stream.read(4))[0] == 3:
                raise RuntimeError('Binary has PT_INTERP; a static executable is required')


def upstream_binary(identifier, destination, cache):
    item = CONFIG[identifier]
    archive = download(item['url'], item['sha256'], cache / 'downloads')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as stream, destination.open('wb') as output:
        member = stream.getmember(item['member'])
        if not member.isfile():
            raise RuntimeError('Expected a regular executable in upstream archive')
        shutil.copyfileobj(stream.extractfile(member), output)
    if digest(destination) != item['binary_sha256']:
        raise RuntimeError('Upstream executable checksum mismatch')
    destination.chmod(0o755)
    static_aarch64(destination)


def package(binary, cache):
    static_aarch64(binary)
    output = ROOT / 'dist/ce'
    output.mkdir(parents=True, exist_ok=True)
    bundle = output / 'bundle'
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.mkdir()
    shutil.copy2(binary, bundle / 'codex-app-server')
    upstream_binary('bwrap', bundle / 'codex-resources/bwrap', cache)
    upstream_binary('code_mode_host', bundle / 'codex-code-mode-host', cache)
    for name in ['LICENSE', 'NOTICE']:
        shutil.copy2(ROOT / name, bundle / name)
    (bundle / 'licenses').mkdir()
    shutil.copy2(ROOT / 'codex-rs/vendor/bubblewrap/COPYING', bundle / 'licenses/bwrap-COPYING')
    shutil.copy2(ROOT / 'ce/README.md', bundle / 'CE-README.md')
    source_patch = output / 'ce-sandbox.patch'
    source_patch.write_bytes(subprocess.check_output(['git', 'diff', CONFIG['upstream_commit'],
        '--', 'codex-rs/linux-sandbox/src'], cwd=ROOT))
    binaries = {name: {'sha256': digest(bundle / name), 'bytes': (bundle / name).stat().st_size}
                for name in ['codex-app-server', 'codex-code-mode-host', 'codex-resources/bwrap']}
    info = dict(upstream_version=CONFIG['upstream_version'], upstream_commit=CONFIG['upstream_commit'],
        repository=CONFIG['repository'], source_commit=git('rev-parse', 'HEAD'),
        source_dirty=bool(git('status', '--porcelain', '--untracked-files=no')),
        release_tag=CONFIG['release_tag'], target=CONFIG['target'], rust=CONFIG['rust'],
        zig=CONFIG['zig']['version'], lock_sha256=digest(ROOT / 'codex-rs/Cargo.lock'),
        sandbox_patch_sha256=digest(source_patch), binaries=binaries)
    if info['source_dirty']:
        raise RuntimeError('Commit tracked source changes before creating release artifacts')
    (bundle / 'build-info.json').write_text(json.dumps(info, indent=2) + '\n')
    shutil.copy2(bundle / 'build-info.json', output / 'build-info.json')
    filename = 'codex-ce-' + CONFIG['release_tag'].removeprefix('ce-v') + '-' + CONFIG['target'] + '.tar.gz'
    archive = output / filename
    epoch = int(git('show', '-s', '--format=%ct', 'HEAD'))
    members = sorted(p for p in bundle.rglob('*') if p.is_file())
    with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as stream:
            for path in members:
                member = stream.gettarinfo(str(path), arcname=str(path.relative_to(bundle)))
                member.uid = member.gid = 0
                member.uname = member.gname = ''
                member.mtime = epoch
                member.mode = 0o755 if str(path.relative_to(bundle)) in binaries else 0o644
                with path.open('rb') as content:
                    stream.addfile(member, content)
    spec = {'version': CONFIG['component_version'], 'label': 'Codex ' + CONFIG['upstream_version'] + ' CE',
        'assets': [{'url': 'https://github.com/' + CONFIG['repository'] + '/releases/download/' + CONFIG['release_tag'] + '/' + filename,
            'filename': filename, 'format': 'tar', 'sha256': digest(archive), 'md5': digest(archive, 'md5'),
            'bytes': archive.stat().st_size, 'expanded_bytes': sum(p.stat().st_size for p in members),
            'files': {str(p.relative_to(bundle)): str(p.relative_to(bundle)) for p in members},
            'executables': list(binaries)}], 'required': list(binaries)}
    (output / 'component.json').write_text(json.dumps(spec, indent=2) + '\n')
    for algorithm, name in [('sha256', 'SHA256SUMS'), ('md5', 'MD5SUMS')]:
        files = [archive, output / 'build-info.json', source_patch, output / 'component.json']
        (output / name).write_text(''.join(digest(p, algorithm) + '  ' + p.name + '\n' for p in files))
    print(json.dumps({'archive': str(archive), 'sha256': digest(archive), 'source_commit': info['source_commit']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['test', 'build'])
    parser.add_argument('--cache', type=Path, default=ROOT / '.cache/ce')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    cache = args.cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    env = environment(cache, args.jobs)
    bootstrap(cache, env)
    test(cache, env)
    if args.action == 'build':
        run([cache / 'cargo/bin/cargo', 'build', '--locked', '--release', '--target', CONFIG['target'],
             '-p', 'codex-app-server', '--bin', 'codex-app-server'],
            cwd=ROOT / 'codex-rs', env=cross_environment(cache, env))
        package(cache / 'target' / CONFIG['target'] / 'release/codex-app-server', cache)


if __name__ == '__main__':
    main()
