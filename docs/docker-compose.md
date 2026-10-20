# Docker Compose deployment

The stack runs one persistent `gateway`, a one-shot `init`, and an on-demand
`issuer`. All use the same image and UID/GID `10001:10001`. Only signing keys
persist; the gateway remains stateless.

## Configure and start

From the repository root, with Docker Compose v2 or newer:

```sh
cp deploy/gitvend.example.json deploy/gitvend.json
mkdir -m 700 secrets
```

Replace `myorg` in **all three places** in `deploy/gitvend.json`: the signing
key's owners, provider's allowed owners, and protected-branch deny.
Repository creation is disabled; enable `allow_creation` only if needed.

Put your GitHub HTTPS access token in `secrets/github_token`, with no other
content. The gateway reads the Compose secret at `/run/secrets/github_token`.
Keep the host directory private and make the individually mounted file readable
by the container's UID 10001. For a directory owned by your host account:

```sh
chmod 700 secrets
chmod 444 secrets/github_token
docker compose up -d --build
docker compose ps -a
curl --fail http://127.0.0.1:8443/healthz
```

The directory restricts host access; the file mode lets the non-root container
read the mounted secret. Local Compose secrets are file mounts, not an encrypted
secret store. The config must also be readable by UID 10001. Local config,
secrets, `.env`, and JWTs are gitignored; the build context includes only Go code
and module files.

`init` exits once keys are ready, then `gateway` starts. `issuer` is in the
`tools` profile, so normal `up` does not start it. Explicit `compose run issuer`
activates it automatically. See Docker's [profile behavior](https://docs.docker.com/compose/how-tos/profiles/).

Optional settings in the environment or root `.env` file:

| Variable | Default |
| --- | --- |
| `GITVEND_CONFIG` | `./deploy/gitvend.json` |
| `GITHUB_TOKEN_FILE` | `./secrets/github_token` |
| `GITVEND_PORT` | `8443` (host loopback only) |
| `GITVEND_IMAGE` | `gitvend:local` |

Once a release image is published, set
`GITVEND_IMAGE=ghcr.io/colony-2/gitvend:vX.Y.Z` in `.env` using an actual release
tag or digest, then run `docker compose --profile tools pull` and
`docker compose up -d --no-build`. Keep that setting for issuer commands too.
A private GHCR package requires registry login; the repository owner can make
the package public after first publication.

## HTTPS endpoint

The default listener is HTTP on container port 8080, published **only** on host
loopback port 8443. Put an existing HTTPS reverse proxy on the host in front of
`http://127.0.0.1:8443`; agents use its public HTTPS address.

For a proxy container, attach it to the Compose network and target
`http://gateway:8080`. Treat that network as trusted. Preserve `Authorization`
and `Git-Protocol`, stream bodies, and align request sizes/timeouts with Gitvend.
Upstream GitHub connections remain HTTPS.
See [TLS terminator configuration](../README.md#running-behind-a-tls-terminator).
`/healthz` checks liveness only; use `git ls-remote` through the public HTTPS
endpoint to validate actual GitHub access.

## Issue a JWT

After startup:

```sh
(umask 077
 docker compose run --rm -T --no-deps issuer \
   -subject agent-47 -ttl 15m \
   -permission 'github.com/myorg/project#main:r' \
   -permission 'github.com/myorg/project#agents/47/*:rw' \
   > agent-47.jwt)
```

The issuer reads the private key, writes the JWT to stdout, and exits. `--rm`
removes the container; `-T` avoids terminal formatting. No issuer process or
signing API runs continuously. Deliver the JWT through your own secret mechanism.

Defaults are key `/var/lib/gitvend/private/signing.key`, key ID `compose-1`,
issuer `compose`, and audience `gitvend`, matching the example config. Additional
flags override them. Supported properties also include `-policy-revision` and
`-max-token-bytes`; arbitrary custom claims are unsupported. Increase the gateway's
`max_token_lifetime_seconds` before issuing tokens longer than its 15-minute default.

To use a grant file instead of permissions:

```sh
(umask 077
 docker compose run --rm -T --no-deps \
   -v "$PWD/examples/grant.json:/run/grant.json:ro" issuer \
   -subject agent-47 -grant /run/grant.json > agent-47.jwt)
```

Edit the grant's organization/repository names and make it readable by UID 10001.
Host redirection avoids `-output` paths referring to the container filesystem.

## Keys and operations

`signing-private` is mounted only by `init` and `issuer`; `signing-public` is
mounted read-only by the gateway. The issuer's private mount is also read-only.
Only the gateway receives the GitHub secret. Init and issuer have no networking.

`keygen -if-missing` locks initialization, validates existing keys, and never
overwrites them. It atomically commits the private key first and recovers a
missing public key from it after interruption. Corrupt keys, mismatched pairs,
or a public key without its private key fail startup; restore the matching
backup. Parent directories must exist. Use local Docker volumes; distributed
filesystem locking is outside this deployment's scope.

Named volumes survive recreation, upgrades, and `docker compose down`.
**`docker compose down -v` deletes the signing keys.** Keep the Compose project
name stable across upgrades/moves, since changing it selects different volumes.

Back up both volumes after initialization:

```sh
(umask 077
 docker compose run --rm -T --no-deps --entrypoint tar init \
   -C /var/lib/gitvend -cf - private public > signing-backup.tar)
```

Protect this archive as a private key. Restore both directories into their
corresponding volumes with the gateway stopped, preserving UID/GID 10001 and
private-file mode 0600. Do not remove the lock file during initialization.

For rotation, run `docker compose run --rm --no-deps init keygen` with new
`-private` and `-public` filenames in the existing volume directories. Add the
new public key under a new ID in config, reload, and pass the new `-key` and
`-kid` to `issuer`. Keep the original pair for the default initializer; retain
old verification keys until their tokens expire, including clock tolerance.

```sh
docker compose kill -s SIGHUP gateway
docker compose logs --tail 50 gateway
```

Reload after changing denies or token-file contents. If a bind-mounted file
was replaced by rename, recreate the gateway to refresh the mount:
`docker compose up -d --force-recreate gateway`. Listener/TLS changes also require
recreation. Compose allows 15 seconds to stop, covering Gitvend's 10-second drain.

## Verification

`make check` tests concurrent initialization, recovery, corrupt state rejection,
key reuse and token verification, plus the existing gateway suite.
`make test-compose` builds and tests an isolated Compose project with a fake
GitHub token: startup, health, on-demand issuance, volume isolation, denied
requests, and JWT survival across container recreation. It requires Docker,
Compose v2 or newer and Python 3, uses no GitHub credentials, and removes only its own
test volumes. CI runs it before releases.
