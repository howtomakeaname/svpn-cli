#!/usr/bin/env python3
"""Exercise the actual CLI forwarding path with ephemeral SM2 CA and dual leaves."""
import argparse, hashlib, json, os, shlex, socket, subprocess, tempfile, threading, time, statistics
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
parser = argparse.ArgumentParser(description='Linux interoperability test against a locally built GmSSL; no VPN credentials or external service required.')
parser.add_argument('--cli', type=Path, required=True)
parser.add_argument('--gmssl-source', type=Path, default=ROOT / '.cache/GmSSL')
parser.add_argument('--gmssl-build', type=Path, default=ROOT / '.cache/GmSSL-build')
parser.add_argument('--repetitions', type=int, default=2)
parser.add_argument('--size-mib', type=int, default=1)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
if not 1 <= args.repetitions <= 20 or not 1 <= args.size_mib <= 64:
    parser.error('repetitions must be 1..20 and size-mib must be 1..64')
cli_binary = str(args.cli.resolve())
source = args.gmssl_source.resolve()
build = args.gmssl_build.resolve()
gmssl = str(build / 'bin/gmssl')
with tempfile.TemporaryDirectory(prefix='svpn-tlcp-interop-') as temporary:
    folder = Path(temporary)
    # GmSSL public struct layouts depend on the exact enabled algorithm macros.
    # This C fixture is test-only; product binaries remain pure Go.
    definition = next((line for line in (build / 'CMakeFiles/gmssl.dir/flags.make').read_text().splitlines() if line.startswith('C_DEFINES = ')))
    gateway = str(folder / 'gateway')
    subprocess.run(['cc', '-O2', *shlex.split(definition.partition(' = ')[2]), '-I' + str(source / 'include'), str(ROOT / 'scripts/interop/gmssl_gateway.c'), str(build / 'bin/libgmssl.a'), '-ldl', '-lpthread', '-o', gateway], check=True)

    def command(*args):
        result = subprocess.run([gmssl, *args], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('GmSSL certificate fixture command failed: ' + result.stderr)
    for role in ['ca', 'sign', 'enc']:
        command('sm2keygen', '-pass', 'temporary-interop-only', '-out', str(folder / (role + '.key')))
    command('certgen', '-CN', 'Interop Root', '-serial_len', '16', '-days', '1', '-key', str(folder / 'ca.key'), '-pass', 'temporary-interop-only', '-ca', '-path_len_constraint', '1', '-key_usage', 'keyCertSign', '-key_usage', 'cRLSign', '-out', str(folder / 'ca.pem'))
    for role, usage in [('sign', 'digitalSignature'), ('enc', 'keyEncipherment')]:
        command('reqgen', '-CN', 'gateway.example', '-key', str(folder / (role + '.key')), '-pass', 'temporary-interop-only', '-out', str(folder / (role + '.csr')))
        command('reqsign', '-in', str(folder / (role + '.csr')), '-serial_len', '16', '-days', '1', '-cacert', str(folder / 'ca.pem'), '-key', str(folder / 'ca.key'), '-pass', 'temporary-interop-only', '-key_usage', usage, '-subject_dns_name', 'gateway.example', '-ext_key_usage', 'serverAuth', '-out', str(folder / (role + '.pem')))
    (folder / 'chain.pem').write_bytes((folder / 'sign.pem').read_bytes() + (folder / 'enc.pem').read_bytes() + (folder / 'ca.pem').read_bytes())
    (folder / 'keys.pem').write_bytes((folder / 'sign.key').read_bytes() + (folder / 'enc.key').read_bytes())
    output = []
    for suite, name in [(57427, 'ECC_SM4_GCM_SM3'), (57363, 'ECC_SM4_CBC_SM3')]:
        errors = (folder / 'server.log').open('w')
        server = subprocess.Popen([gateway, str(folder / 'chain.pem'), str(folder / 'keys.pem'), str(suite)], stdout=subprocess.PIPE, stderr=errors, text=True)
        cli = None
        try:
            port = int(server.stdout.readline())
            session = {'version': 1, 'gateway': 'https://127.0.0.1:' + str(port), 'gateway_tls': 'tlcp', 'server_name': 'gateway.example', 'ca_file': str(folder / 'ca.pem'), 'expires_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 300)), 'resources': [{'address': 'inside.example:443', 'ticket': {'ST': 'local-interop-fixture', 'UserName': 'local-test', 'DeviceID': 'local-test', 'Protocol': 'tcp'}, 'max_connections': 20}]}
            path = folder / 'session.json'
            path.write_text(json.dumps(session))
            path.chmod(384)
            cli = subprocess.Popen([cli_binary, '--json', 'forward', '--session', str(path), '--target', 'inside.example:443', '--listen', '127.0.0.1:0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            ready = json.loads(cli.stdout.readline())
            assert ready['ok']
            host, port = ready['data']['listen'].rsplit(':', 1)
            for repeat in range(args.repetitions):
                started = time.perf_counter()
                client = socket.create_connection((host, int(port)), timeout=10)
                client.settimeout(10)
                banner = b''
                while len(banner) < len(b'independent-gmssl\n'):
                    part = client.recv(len(b'independent-gmssl\n') - len(banner))
                    if not part:
                        raise RuntimeError('TLCP CONNECT ended before GmSSL banner')
                    banner += part
                assert banner == b'independent-gmssl\n'
                cold_ms = (time.perf_counter() - started) * 1000
                payload = bytes(range(256)) * (args.size_mib * 1024 * 1024 // 256)
                expected = hashlib.sha256(payload).hexdigest()
                received = {}

                def receive():
                    digest = hashlib.sha256()
                    count = 0
                    try:
                        while count < len(payload):
                            data = client.recv(min(65536, len(payload) - count))
                            if not data:
                                raise RuntimeError('partial TLCP echo')
                            digest.update(data)
                            count += len(data)
                        received.update(bytes=count, sha256=digest.hexdigest())
                    except Exception as e:
                        received['error'] = str(e)
                started = time.perf_counter()
                reader = threading.Thread(target=receive)
                reader.start()
                client.sendall(payload)
                reader.join(timeout=15)
                elapsed = time.perf_counter() - started
                assert not reader.is_alive() and 'error' not in received and (received['bytes'] == len(payload)) and (received['sha256'] == expected), received
                client.close()
                row = {'suite': name, 'repeat': repeat + 1, 'bytes_each_direction': len(payload), 'seconds': elapsed, 'mib_per_second_each_direction': args.size_mib / elapsed, 'connect_ms': cold_ms}
                output.append(row)
            cli.terminate()
            assert cli.wait(timeout=10) == 0
            values = [r['mib_per_second_each_direction'] for r in output if r['suite'] == name]
            print(name, ':', args.repetitions, 'verified batches of', args.size_mib, 'MiB per direction; mean', round(statistics.mean(values), 2), 'MiB/s; sample SD', round(statistics.stdev(values), 2) if len(values) > 1 else 'N/A', flush=True)
        except Exception:
            print('GmSSL helper exit:', server.poll())
            errors.flush()
            print((folder / 'server.log').read_text()[-2000:])
            raise
        finally:
            if cli and cli.poll() is None:
                cli.terminate()
                cli.wait(timeout=10)
            server.terminate()
            server.wait(timeout=10)
            errors.close()
    if args.output:
        args.output.write_text(json.dumps({'server': 'GmSSL v3.2.0', 'scope': 'loopback interoperability; no production VPN gateway', 'samples': output}, indent=2))
        args.output.chmod(384)
print('Ephemeral SM2 private keys and certificate fixtures removed.')
