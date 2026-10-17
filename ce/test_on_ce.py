#!/usr/bin/env python3
"""Offline CoreELEC sandbox checks; no addon, account, or cloud dependency."""
import argparse
import json
import os
from pathlib import Path
import queue
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading


class Connection:
    def __init__(self, binary, home, work):
        env = dict(os.environ, CODEX_HOME=str(home), LC_ALL='C', LANG='C')
        self.errors = (home / 'server-stderr.log').open('w+')
        args = [str(binary), '--listen', 'stdio://', '--session-source', 'exec']
        for key, value in {'analytics.enabled': False, 'feedback.enabled': False,
                           'history.persistence': 'none', 'features.shell_snapshot': False,
                           'web_search': 'disabled', 'mcp_servers': {}, 'approval_policy': 'never',
                           'sandbox_mode': 'workspace-write'}.items():
            args += ['-c', key + '=' + ('{}' if value == {} else json.dumps(value))]
        self.process = subprocess.Popen(args, cwd=work, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.errors, text=True, bufsize=1)
        self.messages = queue.Queue()
        self.sequence = 0
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        try:
            for line in self.process.stdout:
                self.messages.put(json.loads(line))
        except Exception as error:
            self.messages.put(error)
        finally:
            self.messages.put(EOFError('app-server exited'))

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + '\n')
        self.process.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        identifier = self.sequence
        self.send({'id': identifier, 'method': method, 'params': params})
        while True:
            message = self.messages.get(timeout=40)
            if isinstance(message, Exception):
                raise message
            if message.get('id') == identifier and 'method' not in message:
                if 'error' in message:
                    raise RuntimeError(str(message['error']))
                return message['result']

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.errors.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {'ok': False, 'cloud_request': False, 'production_changed': False, 'cases': []}
    with tempfile.TemporaryDirectory(prefix='codex-ce-check-', dir=args.output.parent) as directory:
        base = Path(directory)
        # Never modify the supplied bundle, even when testing its integrity guard.
        binaries = base / 'bundle'
        (binaries / 'codex-resources').mkdir(parents=True)
        for name in ['codex-app-server', 'codex-resources/bwrap']:
            shutil.copy2(bundle / name, binaries / name)
        home, work = base / 'home', base / 'work'
        home.mkdir(mode=0o700)
        work.mkdir()
        (work / '.git').mkdir()
        (work / '.git/config').write_text('ORIGINAL')
        (base / 'outside').mkdir()
        (base / 'private-marker').write_text('TEST_FIXTURE_ONLY')
        (base / 'private-marker').chmod(0o600)
        (work / 'outside-link').symlink_to(base / 'outside', target_is_directory=True)
        connection = Connection(binaries / 'codex-app-server', home, work)
        try:
            connection.request('initialize', {'clientInfo': {'name': 'ce_sandbox_check', 'version': '1'},
                'capabilities': {'experimentalApi': True}})
            connection.send({'method': 'initialized'})
            policy = {'type': 'workspaceWrite', 'writableRoots': [str(work)], 'networkAccess': False}

            def execute(name, command, succeeds, selected_policy=None):
                result = connection.request('command/exec', {'command': ['/bin/sh', '-c', command],
                    'cwd': str(work), 'timeoutMs': 10000, 'sandboxPolicy': selected_policy or policy})
                report['cases'].append({'name': name, **result})
                if (result.get('exitCode') == 0) != succeeds:
                    raise RuntimeError('Unexpected sandbox outcome: ' + name)
                return result

            python = shlex.quote(sys.executable) + ' -c '
            execute('arm32_shell_and_python', 'printf SHELL_OK; ' + python + shlex.quote('print("PYTHON_OK")'), True)
            execute('arm64_child', shlex.quote(str(binaries / 'codex-resources/bwrap')) + ' --version', True)
            execute('workspace_write', 'printf INSIDE > normal.txt && test "$(cat normal.txt)" = INSIDE && rm normal.txt', True)
            execute('outside_write_denied', 'printf WRONG > ' + shlex.quote(str(base / 'outside/blocked')), False)
            execute('existing_metadata_denied', 'printf WRONG > .git/config', False)
            execute('missing_metadata_denied', 'mkdir -p .aws && printf WRONG > .aws/config', False)
            execute('symlink_escape_denied', 'printf WRONG > outside-link/blocked', False)
            execute('read_only_denied', 'printf WRONG > blocked-readonly', False, {'type': 'readOnly'})
            network = '''import socket,ctypes,os,errno
try:
 socket.socket(socket.AF_INET,socket.SOCK_STREAM)
except OSError as e:
 assert e.errno==errno.EPERM,e
else:
 raise RuntimeError('IP socket was allowed')
libc=ctypes.CDLL(None,use_errno=True)
for number in (376,377):
 ctypes.set_errno(0)
 assert libc.syscall(number,os.getpid(),0,0,0,0,0)==-1 and ctypes.get_errno()==errno.EPERM
print('NETWORK_AND_MEMORY_DENIED')
'''
            execute('arm32_network_and_memory_denied', python + shlex.quote(network), True)
            network_allowed = '''import socket,errno
with socket.socket(socket.AF_INET,socket.SOCK_STREAM):pass
try:
 socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM)
except OSError as e:
 assert e.errno==errno.EPERM,e
else:
 raise RuntimeError('VM socket was allowed')
print('IP_ALLOWED_VM_SOCKET_DENIED')
'''
            execute('network_enabled_preserves_vm_socket_guard', python + shlex.quote(network_allowed), True,
                    dict(policy, networkAccess=True))
            host_proc = '/proc/' + str(os.getpid()) + '/root' + str(base / 'private-marker')
            code = 'from pathlib import Path\ntry:\n Path(' + repr(host_proc) + ').read_text()\nexcept (PermissionError,FileNotFoundError):\n print("HOST_PROC_BLOCKED")\nelse:\n raise RuntimeError("host proc root accessible")'
            execute('host_proc_root_denied', python + shlex.quote(code), True)
            with (base / 'private-marker').open('rb') as fixture:
                paths = ['/proc/' + str(os.getpid()) + '/mem',
                         '/proc/' + str(os.getpid()) + '/fd/' + str(fixture.fileno())]
                code = ('from pathlib import Path\nfor name in ' + repr(paths) + ':\n'
                    ' try:\n  stream=Path(name).open("rb")\n'
                    ' except (PermissionError,FileNotFoundError):\n  pass\n'
                    ' else:\n  stream.close();raise RuntimeError("host proc descriptor accessible")\n'
                    'print("HOST_PROC_MEMORY_AND_FD_BLOCKED")')
                execute('host_proc_memory_and_fd_denied', python + shlex.quote(code), True)
            bwrap = binaries / 'codex-resources/bwrap'
            with bwrap.open('ab') as stream:
                stream.write(b'\0')
            result = execute('bundled_bwrap_digest_enforced', 'printf SHOULD_NOT_RUN', False)
            assert 'digest mismatch' in result.get('stderr', '')
            assert 'SHOULD_NOT_RUN' not in result.get('stdout', '')
            report['fixtures_intact'] = (work / '.git/config').read_text() == 'ORIGINAL' and not (
                base / 'outside/blocked').exists() and not (work / 'blocked-readonly').exists()
            assert report['fixtures_intact']
            report['ok'] = True
        except Exception as error:
            report['error'] = str(error)[:500]
        finally:
            connection.close()
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'ok': report['ok'], 'cases': len(report['cases']), 'error': report.get('error')}))
    if not report['ok']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
