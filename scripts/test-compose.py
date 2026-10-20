#!/usr/bin/env python3
"""Exercise a disposable Compose project without GitHub credentials."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="gitvend-compose-") as tmp:
        temp = Path(tmp)
        config = temp / "gitvend.json"
        config.write_bytes((ROOT / "deploy/gitvend.example.json").read_bytes())
        config.chmod(0o444)
        secret = temp / "github_token"
        secret.write_text("compose-test-placeholder\n")
        secret.chmod(0o444)
        env = dict(os.environ, GITVEND_CONFIG=str(config),
                   GITHUB_TOKEN_FILE=str(secret), GITVEND_PORT="0",
                   GITVEND_IMAGE="gitvend:compose-test")
        project = "gitvend-test-" + uuid.uuid4().hex[:12]
        prefix = ["docker", "compose", "-p", project, "-f", str(ROOT / "compose.yaml")]

        def compose(*args, capture=False):
            return subprocess.run(prefix + list(args), env=env, cwd=ROOT,
                                  check=True, text=True,
                                  stdout=subprocess.PIPE if capture else None).stdout

        def request(path, token, data=None):
            req = urllib.request.Request(
                base + path, data=data,
                headers={"Authorization": "Basic " + base64.b64encode(
                    ("git:" + token).encode()).decode(),
                    "Content-Type": "application/x-git-receive-pack-request"})
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    return response.status
            except urllib.error.HTTPError as error:
                error.close()
                return error.code

        try:
            compose("config", "--quiet")
            compose("build", "gateway")
            compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "60")
            running = compose("ps", "--services", "--status", "running", capture=True).split()
            assert running == ["gateway"], running
            # The only persistent volume visible to the server holds public keys.
            cid = compose("ps", "-q", "gateway", capture=True).strip()
            inspection = json.loads(subprocess.check_output(["docker", "inspect", cid]))[0]
            volume_mounts = [m for m in inspection["Mounts"] if m["Type"] == "volume"]
            assert len(volume_mounts) == 1
            assert volume_mounts[0]["Destination"] == "/var/lib/gitvend/public"
            assert not volume_mounts[0]["RW"]
            assert inspection["Config"]["User"] == "10001:10001"
            assert inspection["HostConfig"]["ReadonlyRootfs"]

            original_public = compose("exec", "-T", "gateway", "cat",
                                      "/var/lib/gitvend/public/signing.pub", capture=True)
            token = compose("run", "--rm", "-T", "--no-deps", "issuer",
                            "-subject", "compose-test", "-ttl", "5m",
                            "-permission", "github.com/myorg/project#agents/*:rw",
                            capture=True).strip()
            assert len(token.split(".")) == 3, "issuer output is not a JWT"
            # This deliberately omits Git-Protocol: 400 proves the token and
            # repository grant passed validation, without contacting GitHub.
            base = "http://" + compose("port", "gateway", "8080", capture=True).strip()
            allowed = "/github/myorg/project.git/info/refs?service=git-upload-pack"
            denied = "/github/myorg/other.git/info/refs?service=git-upload-pack"
            assert request(allowed, token) == 400
            assert request(denied, token) == 403
            assert request(allowed, "invalid") == 401
            command = ("1" * 40 + " " + "2" * 40 +
                       " refs/heads/main\0report-status\n").encode()
            push = f"{len(command) + 4:04x}".encode() + command + b"0000"
            assert request("/github/myorg/project.git/git-receive-pack", token, push) == 403

            compose("down")  # Preserve named volumes.
            compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "60")
            base = "http://" + compose("port", "gateway", "8080", capture=True).strip()
            assert compose("exec", "-T", "gateway", "cat",
                           "/var/lib/gitvend/public/signing.pub", capture=True) == original_public
            assert request(allowed, token) == 400, "old JWT failed after container recreation"
            print("Compose startup, isolation, issuance, authorization and persistence passed.")
        except Exception:
            compose("logs", "--no-color")
            raise
        finally:
            # Only this randomly named test project's volumes are removed.
            compose("--profile", "tools", "down", "-v", "--remove-orphans")


if __name__ == "__main__":
    main()
