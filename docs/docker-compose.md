# Docker Compose deployment

The stack runs one persistent `gateway`, a one-shot `init`, and an on-demand
`issuer`. All use the same image and UID/GID `10001:10001`. Only signing keys
persist; the gateway remains stateless.

## Configure and start

Download a [release archive](https://github.com/colony-2/gitvend/releases) and
extract it into your deployment directory. Use a release containing `compose.yaml`,
`compose.config.yaml`, and `deploy/gitvend.default.yaml`; keep this layout for the
commands below. Docker Compose v2 or newer is required; no local build is needed.

Set `GITVEND_IMAGE` to the matching published image tag (replace `vX.Y.Z` with your
release version), then pull the image and start the stack:

```sh
export GITVEND_IMAGE='ghcr.io/colony-2/gitvend:vX.Y.Z'
export GITHUB_TOKEN='your-github-access-token'
docker compose --profile tools pull
docker compose up -d --no-build
docker compose ps -a
curl --fail http://127.0.0.1:8443/healthz
```

Keep both variables exported for later Compose commands, or save them in a
private `.env` file in the deployment directory. Pin a release tag or digest
when upgrading. A private GHCR package requires registry login.

`GITHUB_TOKEN` is a GitHub HTTPS access token,
not an SSH key. Keep it exported for subsequent Compose commands, or put
`GITHUB_TOKEN=...` in a private `.env` file. Compose passes it
only to the gateway, never to the build, initializer, or issuer.

The image includes [default configuration](../deploy/gitvend.default.yaml);
no local config or token file is needed. It accepts any owner on `github.com`,
using explicit `["*"]` provider and signing-key owner lists. Each request must
still match the agent JWT's permissions and the GitHub token's actual access.
Writes/deletions to `main` and `master` are denied for all owners, and repository
creation is disabled. No GitHub owner discovery or extra API scope is needed.
Newly accessible owners work without regenerating config.

`init` exits once keys are ready, then `gateway` starts. `issuer` is in the
`tools` profile, so normal `up` does not start it. Explicit `compose run issuer`
activates it automatically. See Docker's [profile behavior](https://docs.docker.com/compose/how-tos/profiles/).

Optional settings in the environment or root `.env` file:

| Variable | Default |
| --- | --- |
| `GITVEND_PORT` | `8443` (host loopback only) |
| `GITVEND_IMAGE` | Set explicitly to your published image tag; `gitvend:local` is the source-build default. |

## HTTPS endpoint

The default listener is HTTP on container port 8080, published **only** on host
loopback port 8443. Put an existing HTTPS reverse proxy on the host in front of
`http://127.0.0.1:8443`; agents use its public HTTPS address.

For a proxy container, attach it to the Compose network and target
`http://gateway:8080`. Treat that network as trusted. Preserve `Authorization`
and `Git-Protocol`, stream bodies, and align request sizes/timeouts with Gitvend.
Upstream GitHub connections remain HTTPS.
See [TLS terminator configuration](gateway.md#running-behind-a-tls-terminator).
`/healthz` checks liveness only; use `git ls-remote` through the public HTTPS
endpoint to validate actual GitHub access.

## Issue a JWT

After startup:

```sh
(umask 077
 docker compose run --rm -T --no-deps issuer \
   --subject agent-47 --ttl 15m \
   --permission 'github.com/myorg/project#main:r' \
   --permission 'github.com/myorg/project#agents/47/*:rw' \
   > agent-47.jwt)
```

The issuer reads the private key, writes the JWT to stdout, and exits. `--rm`
removes the container; `-T` avoids terminal formatting. No issuer process or
signing API runs continuously. Deliver the JWT through your own secret mechanism.

Defaults are key `/var/lib/gitvend/private/signing.key`, key ID `compose-1`,
issuer `compose`, and audience `gitvend`, matching the bundled config. Additional
flags override them. Supported properties also include `--policy-revision` and
`--max-token-bytes`; arbitrary custom claims are unsupported. Increase the gateway's
`max_token_lifetime_seconds` in a custom config before issuing tokens longer than
its 15-minute default.

To use a grant file instead of permissions:

```sh
(umask 077
 docker compose run --rm -T --no-deps \
   -v "$PWD/examples/grant.json:/run/grant.json:ro" issuer \
   --subject agent-47 --grant /run/grant.json > agent-47.jwt)
```

Edit the grant's organization/repository names and make it readable by UID 10001.
Host redirection avoids `--output` paths referring to the container filesystem.

## Optional custom configuration

For an explicit owner allowlist, repository creation, signing-key rotation,
or other advanced settings, copy the bundled config and use the optional overlay:

```sh
cp deploy/gitvend.default.yaml deploy/gitvend.yaml
# Edit deploy/gitvend.yaml, then:
docker compose -f compose.yaml -f compose.config.yaml up -d --no-build
```

The overlay mounts `deploy/gitvend.yaml` read-only (override its path with
`GITVEND_CONFIG`). Keep it readable by UID 10001 and use both `-f` flags for
subsequent Compose operations. To restrict organizations, replace `["*"]` in
both `keys[].owners["github.com"]` and `providers[].allowed_owners` with lowercase
owner names. Preserve the `env:GITHUB_TOKEN` credential reference.

## Keys and operations

`signing-private` is mounted only by `init` and `issuer`; `signing-public` is
mounted read-only by the gateway. The issuer's private mount is also read-only.
Only the gateway receives `GITHUB_TOKEN`. Init and issuer have no networking.

`keygen --if-missing` locks initialization, validates existing keys, and never
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

For signing-key rotation, enable custom configuration, then run
`docker compose run --rm --no-deps init keygen` with new
`--private` and `--public` filenames in the existing volume directories. Add the
new public key under a new ID in config, reload, and pass the new `--key` and
`--kid` to `issuer`. Keep the original pair for the default initializer; retain
old verification keys until their tokens expire, including clock tolerance.

```sh
docker compose kill -s SIGHUP gateway
docker compose logs --tail 50 gateway
```

Reload after changing denies or verification keys in custom config. If a bind-mounted file
was replaced by rename, recreate the gateway to refresh the mount:
`docker compose up -d --no-build --force-recreate gateway`. Listener/TLS changes also require
recreation. Compose allows 15 seconds to stop, covering Gitvend's 10-second drain.
To rotate the GitHub token, update the exported `GITHUB_TOKEN` (or `.env`) and
run `docker compose up -d --no-build --force-recreate gateway`; SIGHUP cannot change a
running container's environment.

## Verify the deployment

Check `docker compose ps -a`, the gateway logs, and `/healthz`, then use a real
agent credential with `git ls-remote` against the public HTTPS endpoint. The
health endpoint alone does not confirm GitHub access.

For creation controls, including visibility and GitHub features, see the
[gateway guide](gateway.md#repository-creation-defaults). The bundled container
configuration disables creation until you enable it in a custom config.

Source builds and automated container tests are covered in the
[developer guide](development.md#container-development).
