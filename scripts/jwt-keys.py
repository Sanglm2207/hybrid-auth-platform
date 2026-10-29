#!/usr/bin/env python3
"""Stage/activate/retire JWKs using atomic private manifest writes. Requires Python 3 and JDK 25."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('operation', choices=['init', 'stage', 'activate', 'retire', 'list'])
parser.add_argument('--manifest', default='keys/jwt-key-set.json')
parser.add_argument('--kid', default='local-1')
parser.add_argument('--private-pem', default='keys/private.pem')
args = parser.parse_args()
if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}', args.kid): parser.error('Invalid kid')
path = Path(args.manifest)
if args.operation == 'init':
    if path.exists(): parser.error('Manifest already exists; refusing to replace it')
    manifest = {'activeKid': args.kid, 'keys': [], 'retiredKids': [], 'retireAfter': {}}
else:
    if not path.exists(): parser.error('Initialize the manifest first')
    manifest = json.loads(path.read_text())
ids = {key['kid'] for key in manifest['keys']}
if args.operation == 'list':
    for key in manifest['keys']: print(key['kid'] + (' (active)' if key['kid'] == manifest['activeKid'] else ''))
    raise SystemExit()
if args.operation in ['init', 'stage']:
    if args.kid in ids or args.kid in manifest.get('retiredKids', []): parser.error('kid was already used; choose a new ID')
    command = ['java', str(Path(__file__).with_name('GenerateRsaJwk.java')), args.kid]
    if args.operation == 'init': command.append(args.private_pem)
    generated = subprocess.run(command, capture_output=True, text=True)
    if generated.returncode != 0: parser.error('RSA generation/import failed; check JDK 25 and the PKCS8 PEM file')
    manifest['keys'].append(json.loads(generated.stdout))
elif args.operation == 'activate':
    if args.kid not in ids: parser.error('Stage this kid first')
    if manifest['activeKid'] != args.kid:
        # 15-minute access TTL + clock skew + reload/operational margin.
        manifest.setdefault('retireAfter', {})[manifest['activeKid']] = int(time.time()) + 1020
    manifest['activeKid'] = args.kid
elif args.operation == 'retire':
    if args.kid not in ids: parser.error('Unknown kid')
    if args.kid == manifest['activeKid']: parser.error('Cannot retire the active key')
    if time.time() < manifest.get('retireAfter', {}).get(args.kid, 0):
        parser.error('Keep the old key for at least 17 minutes after activation and verify all Auth nodes switched')
    manifest['keys'] = [key for key in manifest['keys'] if key['kid'] != args.kid]
    manifest.setdefault('retiredKids', []).append(args.kid)
path.parent.mkdir(parents=True, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix='.jwt-', dir=path.parent)
try:
    with os.fdopen(fd, 'w') as output:
        json.dump(manifest, output, indent=2)
        output.write('\n'); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary): os.unlink(temporary)
print('Updated private JWT manifest; no key material displayed. Wait for reload and verify public JWKS.')
