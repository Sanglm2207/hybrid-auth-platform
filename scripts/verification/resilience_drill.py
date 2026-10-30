#!/usr/bin/env python3
"""P6: real JVM graceful shutdown plus isolated dependency failures. No .env is loaded."""
import concurrent.futures
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def graceful_shutdown():
    received = threading.Event()

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            received.set()
            time.sleep(2)
            body = b'{"completed":true}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    java = str(Path(os.environ['JAVA_HOME']) / 'bin/java') if os.environ.get('JAVA_HOME') else shutil.which('java')
    if not os.environ.get('JAVA_HOME') and Path('/opt/homebrew/opt/openjdk/bin/java').exists():
        java = '/opt/homebrew/opt/openjdk/bin/java'
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='hybrid-p6-graceful-') as directory:
            env = dict(os.environ, SERVER_PORT=str(port), AUTH_URL=f'http://127.0.0.1:{upstream.server_port}',
                       AUTH_PROXY_KEY='p6-generated-test-proxy-key-thirty-two-characters',
                       OBSERVABILITY_ENABLED='false', AUDIT_LOG_PATH=directory + '/audit',
                       TELEMETRY_LOG_PATH=directory + '/telemetry')
            with (Path(directory) / 'gateway.log').open('w') as log:
                process = subprocess.Popen([java, '-jar', str(ROOT / 'api-gateway/target/api-gateway-1.0.0.jar')],
                                           env=env, stdout=log, stderr=log)
                for _ in range(300):
                    assert process.poll() is None, 'Gateway exited during startup'
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/actuator/health/readiness', timeout=1):
                            break
                    except (urllib.error.URLError, TimeoutError):
                        time.sleep(.1)
                else:
                    raise AssertionError('Gateway readiness timeout')

                def request():
                    req = urllib.request.Request(f'http://127.0.0.1:{port}/api/v1/auth/login',
                                                 data=b'{}', headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        assert response.status == 200
                        assert json.load(response)['completed']

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(request)
                    assert received.wait(10), 'Request did not reach upstream'
                    process.send_signal(signal.SIGTERM)
                    future.result(timeout=15)
                process.wait(timeout=35)
                log.flush()
                assert 'Graceful shutdown complete' in (Path(directory) / 'gateway.log').read_text()
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=35)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        upstream.shutdown()
        upstream.server_close()


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    result = ROOT / 'reports/resilience/result.json'
    result.unlink(missing_ok=True)
    graceful_shutdown()
    print('P6 graceful shutdown passed: SIGTERM preserved an in-flight HTTP response.', flush=True)
    child = subprocess.Popen(['python3', str(ROOT / 'scripts/verification/hardening_drill.py')],
                             env=dict(os.environ, P6_FAILURE_INJECTION='true', P4_ZAP='false', OBSERVABILITY_ENABLED='false'))
    try:
        assert child.wait(timeout=600) == 0, 'P6 dependency failure drill failed'
    finally:
        if child.poll() is None:
            child.send_signal(signal.SIGINT)
            try:
                child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text(json.dumps({'passed': True, 'checks': [
        'graceful-shutdown', 'redis-loss', 'postgres-loss', 'service-loss', 'readiness',
        'liveness', 'fail-closed', 'recovery', 'transactional-outbox-smtp-retry',
        'concurrent-refresh-replay', 'durable-session-restart']}, indent=2) + '\n')
