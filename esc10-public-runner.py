"""Run a private, owned .NET validation payload on a hosted runner."""

import hashlib
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import traceback
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "out"
OUT.mkdir(exist_ok=True)
KEY = bytes.fromhex(os.environ["ESC10_ID01_KEY"])
AES = AESGCM(KEY)


def unseal(blob):
    return AES.decrypt(blob[:12], blob[12:], None)


def seal(data):
    nonce = secrets.token_bytes(12)
    return nonce + AES.encrypt(nonce, data, None)


def run(command, cwd, log, env):
    log.write("command=" + command[0] + "\n")
    log.flush()
    completed = subprocess.run(command, cwd=cwd, env=env, stdout=log,
                               stderr=subprocess.STDOUT, timeout=600)
    if completed.returncode != 0:
        raise RuntimeError(f"command failed with {completed.returncode}")


success = False
private_log = OUT / "private.log"
payload = ROOT / "payload"
try:
    with private_log.open("w", encoding="utf-8") as log:
        try:
            archive = unseal((ROOT / "esc10-input.enc").read_bytes())
            zip_path = ROOT / "payload.zip"
            zip_path.write_bytes(archive)
            with zipfile.ZipFile(zip_path) as zip_file:
                zip_file.extractall(payload)
            dotnet = shutil.which("dotnet")
            if not dotnet:
                raise RuntimeError("dotnet missing")
            dotnet_root = pathlib.Path(dotnet).resolve().parent
            env = os.environ.copy()
            env["DOTNET_ROOT"] = str(dotnet_root)
            env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
            identity_dll = dotnet_root / "shared" / "Microsoft.AspNetCore.App" / "11.0.0" / "Microsoft.AspNetCore.Identity.dll"
            if not identity_dll.exists():
                raise RuntimeError("official Identity 11.0.0 binary missing")
            log.write("IdentityDLL_SHA256=" + hashlib.sha256(identity_dll.read_bytes()).hexdigest() + "\n")
            project = next(payload.rglob("*.csproj"))
            run([dotnet, "--info"], payload, log, env)
            run([dotnet, "restore", str(project)], payload, log, env)
            run([dotnet, "build", "--no-restore", str(project)], payload, log, env)
            run([sys.executable, str(payload / "probe.py")], payload, log, env)
            if not (payload / "result.json").exists():
                raise RuntimeError("result file missing")
            success = True
        except Exception:
            traceback.print_exc(file=log)
        finally:
            log.flush()
    (OUT / "private-log.enc").write_bytes(seal(private_log.read_bytes()))
    result_path = payload / "result.json"
    if result_path.exists():
        (OUT / "result.enc").write_bytes(seal(result_path.read_bytes()))
finally:
    private_log.unlink(missing_ok=True)
    (ROOT / "payload.zip").unlink(missing_ok=True)

print("encrypted_validation_passed=" + str(success).lower())
sys.exit(0 if success else 1)
