#!/usr/bin/env python3
"""Scan only the disposable drill's loopback User service, using its short-lived JWT.
Docker host networking (Linux) or Docker Desktop (macOS) is required.
"""
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def scan(port, token):
    if platform.system() not in ('Linux', 'Darwin'):
        raise RuntimeError('P4 ZAP requires Linux or macOS Docker Desktop')
    host = '127.0.0.1' if platform.system() == 'Linux' else 'host.docker.internal'
    network = ['--network', 'host'] if platform.system() == 'Linux' else []
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError('Expected an isolated loopback service port')
    # Prove the authenticated endpoint is reachable before invoking the active scanner.
    request = urllib.request.Request(f'http://127.0.0.1:{port}/api/v1/users/me',
                                     headers={'Authorization': f'Bearer {token}'})
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError('ZAP fixture identity is not authorized')
    output = ROOT / 'reports' / 'zap'
    output.mkdir(parents=True, exist_ok=True)
    spec = json.loads((ROOT / 'docs' / 'openapi.json').read_text())
    spec['servers'] = [{'url': f'http://{host}:{port}'}]
    spec['paths'] = {p: v for p, v in spec['paths'].items() if p.startswith('/api/v1/users/')}
    # Docker runs as the caller: scan artifacts remain writable without world-writable repo paths.
    with tempfile.TemporaryDirectory(prefix='p4-zap-') as directory:
        work = Path(directory)
        (work / 'api.json').write_text(json.dumps(spec))
        # Keep the JWT out of process arguments, console logs and uploaded artifacts.
        (work / 'auth.properties').write_text(
            'replacer.full_list(0).description=P4 disposable identity\n'
            'replacer.full_list(0).enabled=true\n'
            'replacer.full_list(0).matchtype=REQ_HEADER\n'
            'replacer.full_list(0).matchstr=Authorization\n'
            'replacer.full_list(0).regex=false\n'
            f'replacer.full_list(0).replacement=Bearer {token}\n')
        os.chmod(work / 'auth.properties', 0o600)
        result = subprocess.run([
            'docker', 'run', '--rm', *network, '--user', f'{os.getuid()}:{os.getgid()}',
            '-e', 'HOME=/tmp', '-v', f'{work}:/zap/wrk:rw',
            'ghcr.io/zaproxy/zaproxy:stable', 'zap-api-scan.py',
            '-t', '/zap/wrk/api.json', '-f', 'openapi', '-J', 'zap.json', '-r', 'zap.html',
            '-z', '-dir /tmp/p4-zap-home -config scanner.maxScanDurationInMins=5 -configfile /zap/wrk/auth.properties'], timeout=900)
        if result.returncode not in (0, 1, 2):
            raise RuntimeError(f'ZAP infrastructure error: {result.returncode}')
        report = json.loads((work / 'zap.json').read_text())
        # ZAP can echo authorization values into request evidence; redact before publishing.
        for name in ('zap.json', 'zap.html'):
            (output / name).write_text((work / name).read_text().replace(token, '[REDACTED]'))
        alerts = [a for site in report.get('site', []) for a in site.get('alerts', [])]
        blocking = [a for a in alerts if int(a['riskcode']) >= 2]
        if not report.get('site'):
            raise RuntimeError('ZAP produced no scanned sites')
        if blocking:
            raise RuntimeError('ZAP medium/high alerts: ' + ', '.join(a['name'] for a in blocking))
        print(f'ZAP passed: {len(alerts)} low/informational alerts; zero medium/high alerts')
