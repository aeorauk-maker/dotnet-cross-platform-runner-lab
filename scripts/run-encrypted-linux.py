#!/usr/bin/env python3
"""Run encrypted, researcher-owned validation input; publish encrypted evidence only."""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile, ZIP_DEFLATED

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

workspace = Path(os.environ['GITHUB_WORKSPACE'])
runner_temp = Path(os.environ['RUNNER_TEMP'])
key = base64.b64decode(os.environ.pop('H4_VALIDATION_KEY'))
if len(key) != 32:
    raise RuntimeError('invalid validation secret length')
blob = base64.b64decode((workspace / 'encrypted/validation.b64').read_text().strip())
work = Path(tempfile.mkdtemp(prefix='h4-validation-', dir=runner_temp))
expanded = work / 'expanded'
expanded.mkdir()
harness_log = expanded / 'harness.log'
encrypted_output = workspace / 'encrypted-run-output.bin'
failed = True

try:
    clear = AESGCM(key).decrypt(blob[:12], blob[28:] + blob[12:28], None)
    archive = work / 'input.zip'
    archive.write_bytes(clear)
    with ZipFile(archive) as z:
        assert z.testzip() is None
        for item in z.infolist():
            target = (expanded / item.filename).resolve()
            assert target == expanded or expanded in target.parents
        z.extractall(expanded)
    archive.unlink()
    with harness_log.open('w') as log:
        process = subprocess.run([sys.executable, 'poc/run_linux.py', '5'],
                                 cwd=expanded, stdout=log, stderr=subprocess.STDOUT,
                                 timeout=1100, check=False)
    report_path = expanded / 'poc/report.json'
    report = json.loads(report_path.read_text()) if report_path.exists() else None
    failed = process.returncode != 0 or not report or bool(report.get('setup_or_run_error'))
except Exception as exc:
    with harness_log.open('a') as log:
        log.write(type(exc).__name__ + ': ' + str(exc) + '\n')
finally:
    evidence = work / 'evidence.zip'
    with ZipFile(evidence, 'w', ZIP_DEFLATED) as z:
        for path in sorted(expanded.rglob('*')):
            if path.is_file():
                z.write(path, path.relative_to(expanded).as_posix())
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, evidence.read_bytes(), None)
    encrypted = nonce + ciphertext[-16:] + ciphertext[:-16]
    encrypted_output.write_bytes(encrypted)
    print('HarnessGated=' + str(not failed))
    print('EncryptedEvidenceSha256=' + hashlib.sha256(encrypted).hexdigest())
    print('EncryptedEvidenceBytes=' + str(len(encrypted)))
    shutil.rmtree(work, ignore_errors=True)

if failed:
    raise RuntimeError('private validation failed; encrypted evidence is available')
