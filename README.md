# gitvend

A Go Git/HTTPS gateway with permissions carried in signed JWTs. Agents use ordinary Git and one gateway credential across their assigned repositories. The gateway holds a shared upstream token and enforces repository, ref-discovery, branch-write, tag and repository-creation permissions before forwarding requests.

Implemented for GitHub and GitHub Enterprise-compatible APIs. Client and upstream Git connections use HTTPS; fetch/ref lookup requires protocol v2, while pushes use Git's normal receive-pack format. The service does not require a GitHub App.

## Install

Published releases are available from [GitHub Releases](https://github.com/colony-2/gitvend/releases) as Linux/macOS archives for amd64 and arm64, with SHA-256 checksums. Each archive contains the `gitvend` executable, documentation and example configuration.

Once the first release is published, install through Go or npm:

```sh
go install github.com/colony-2/gitvend/cmd/gitvend@latest
# Or use the npm wrapper, which downloads and verifies the matching binary:
npm install -g @colony2/gitvend
gitvend version
```

The npm wrapper requires Node 22+ and `tar`. Install scripts must be enabled so it can download the binary from GitHub Releases. Release builds report their release version; local builds report their Git revision when available.

## Build and verify

Requires Go 1.25+ and Git for the integration tests. Supported server platforms are Linux and macOS.

```sh
go build -o gitvend ./cmd/gitvend
go test -race ./...
go vet ./...
```

`make check` runs race tests and vet. `make fuzz` exercises the permission, packet and JSON parsers. The default test suite uses real Git clients and a real `git-http-backend`, with a local GitHub API fixture; it needs neither a GitHub token nor external repository access.

## Start a gateway

1. Create an upstream token whose account can access the intended repositories and create private repositories in the intended organization. The proxy reuses this token across agents. Check organization token approval, workflow-file permissions and access to newly created repositories for your deployment.
2. Generate an issuer key pair on the orchestrator/operator side:

   ```sh
   mkdir -p var
   ./gitvend keygen -private var/signing.key -public var/signing.pub
   ```

3. Copy [examples/gitvend.json](examples/gitvend.json) to `gitvend.json`. Replace `fooorg`, TLS certificate paths and the trusted issuer configuration. Provide `GITHUB_TOKEN` through the process environment or change `secret_ref` to a mounted `file:/path/to/token`. Only the public signing key belongs on the gateway; the orchestrator retains the private key.
4. Run:

   ```sh
   ./gitvend serve -config gitvend.json
   ```

Use a trusted TLS certificate. `allow_http: true` is an explicit option for development or an isolated listener behind a trusted TLS terminator; it is off by default. `allow_http_upstream` is separately off by default and exists for local integration testing. Neither option disables certificate verification for HTTPS.

The configured route in the example is:

```text
https://git-gateway.example/github/fooorg/project.git
```

The `github` URL segment is a server-owned provider alias. Permission strings use the configured Git authority (`github.com`), not that alias. Provider owner lists and signing-key owner lists both constrain access. Overlapping provider routes for the same host/owner are rejected.

## Issue an agent credential

On the trusted orchestrator, issue a short-lived JWT carrying the task's permissions:

```sh
./gitvend sign \
  -key var/signing.key \
  -kid orchestrator-1 \
  -issuer orchestrator \
  -subject agent-47 \
  -audience gitvend \
  -ttl 15m \
  -permission 'github.com/fooorg/project#main:r' \
  -permission 'github.com/fooorg/project#agents/47/*:rw' \
  -permission 'github.com/fooorg/agent-47-*:c' \
  -permission 'github.com/fooorg/agent-47-*#agents/47/*:rw' \
  -output var/agent-47.jwt
```

Alternatively, pass `-grant examples/grant.json`. The file contains `v`, `permissions`, and optional `bindings` mapping canonical `host/owner/repository` names to string-valued provider repository IDs. `-output` replaces the token file atomically with permissions `0600`; without it, `sign` writes the token to stdout. `keygen` refuses to overwrite existing key files.

JWTs use Ed25519 signatures (`alg=EdDSA`, `typ=gitvend+jwt`). Verification requires the configured issuer, key ID and audience plus subject, token ID, issued-at, not-before, expiry and grant version. Unknown fields, duplicate JSON keys, unsupported algorithms and malformed rules are rejected. The gateway needs no issued-token database and never contacts the issuer on a Git request.

Inject the JWT file into the agent's sandbox, for example at `/run/secrets/gitvend.jwt`. Configure the helper in that sandbox, using the installed absolute path to the executable:

```sh
git config --global protocol.version 2
git config --global credential.https://git-gateway.example.helper ''
git config --global --add credential.https://git-gateway.example.helper \
  '/opt/gitvend credential -host git-gateway.example -token-file /run/secrets/gitvend.jwt'

git clone --branch main https://git-gateway.example/github/fooorg/project.git
git -C project push origin HEAD:refs/heads/agents/47/my-task
```

The empty helper entry resets inherited credential helpers for this host. The helper returns the JWT as an HTTPS Basic password only for the exact configured host and port. It ignores Git's `store`/`erase` requests; the orchestrator owns token replacement. `-token-env VARIABLE_NAME` can replace `-token-file` when environment injection is preferable. No token belongs in a clone URL.

Refresh the injected file before expiry. A task's existing token remains usable until its expiry (plus configured clock tolerance) even if the issuer stops renewing it. There is no immediate per-agent revocation list. Removing a signing key or adding a gateway-wide deny rule affects new requests after configuration reload; an admitted transfer may finish within its deadline.

## Permission strings

```text
[!]host/namespace/repository[#ref-selector]:actions
```

| Action | Meaning |
| --- | --- |
| `r` | Read objects by hash and discover matching refs. |
| `w` | Create/update matching refs, including force updates. |
| `d` | Delete matching refs. |
| `c` | Create matching private repositories; use without a ref selector. |

```text
github.com/fooorg/*:r
github.com/fooorg/blue*:rw
github.com/*:r
github.com/fooorg/red#(main|master|link):rw
!github.com/fooorg/*#(main|master):wd
```

Matching allows combine; any matching deny wins. No `#` covers branches and tags; `#*` covers branches only. A `w` or `d` operation also requires read/discovery permission. `r` scoped to a branch hides other refs but deliberately does not block known-hash reads from the same repository. A broad read grant is not narrowed by adding a more specific grant.

See [the complete syntax](docs/permission-syntax.md) for wildcard, alternative, escaping and deny semantics. Inspect a decision without making network calls:

```sh
./gitvend explain \
  -permission 'github.com/fooorg/*:r' \
  -permission 'github.com/fooorg/blue*:w' \
  -permission '!github.com/fooorg/*#main:wd' \
  -repo github.com/fooorg/bluebird \
  -ref refs/heads/main \
  -action ref.update
```

## Provisioning and audit

Repository creation is opt-in twice: the provider must set `allow_creation: true` and the JWT must grant `c` plus an overlapping readable/writable branch. The gateway proves that overlap with bounded automata, including denies. It never guesses a branch name to establish permission.

Creation occurs during receive-pack discovery. Consequently, `git push --dry-run`, abandoned pushes and later branch-policy rejections may leave empty repositories. Clone/fetch never creates repositories. Direct receive-pack POSTs cannot create missing repositories. Created repositories are private and uninitialized; the gateway never changes an existing repository's visibility, deletes it, or silently seeds `main`.

The local database records creation reservations, daily quotas, outcomes and stable repository IDs. Same-repository creation requests are serialized. Conflicts and ambiguous create responses are reconciled by lookup; unresolved attempts remain recorded for the next authorized discovery or operator investigation. Existing enrolled repository names cannot silently bind to a different provider ID after deletion/recreation. New JWT bindings can also explicitly pin an ID.

Every request has an `X-Request-ID`. Audit intent is durable before a push or create is forwarded. Push audit distinguishes success, rejection, partial success and unknown outcomes; HTTP 200 alone is not success. An interrupted push is never automatically retried. A crash can leave an `admitted` record, which must be treated as an unknown outcome.

To inspect the audit journal, stop the server and run:

```sh
./gitvend audit -state var/gitvend.db
```

The first release uses bbolt with an exclusive process lock: **run one gateway instance per state file**. It handles concurrent agents inside that instance. Active-active replicas need a shared transactional state implementation; separate local state files would not share quotas, identity enrollment or provisioning coordination. Preserve and back up the state file. Audit retention/compaction and a metrics export endpoint are not implemented yet.

## Configuration and limits

Send `SIGHUP` to atomically reload public keys, issuer ceilings, upstream token files, deny rules and limits. A failed reload preserves the last valid configuration. Changes to the listener, TLS paths or state-file path require restart. Replacing an environment variable requires restarting the process. Config reload does not rewrite credentials already in use by an admitted operation.

Important defaults:

| Setting | Default |
| --- | --- |
| `max_token_bytes` | 4,096 serialized JWT bytes; configurable up to 32,768 |
| `max_token_lifetime_seconds` | 900 |
| `clock_skew_seconds` | 30 |
| `max_control_bytes` | 4 MiB |
| `max_pack_bytes` | 1 GiB incoming encoded and decoded request body limits |
| `max_concurrent` | 64 active Git requests |
| `request_timeout_seconds` | 1,800 |
| `creates_per_subject_per_day` | 100, grouped by issuer and subject |
| `creates_per_owner_per_day` | 1,000 |

The HTTP server accepts up to 64 KiB of headers. Basic authentication expands a JWT by roughly one-third, so ingress limits must accommodate the configured token budget too. Use `sign -max-token-bytes` with the same budget as the gateway. Oversized grants are rejected, never truncated or broadened.

Creation quotas reserve capacity durably before calling the forge. Uncertain/failed creation attempts conservatively retain the reservation for that day; retrying the same recorded attempt does not reserve again. Existing repositories do not consume creation quota. Incoming packs are streamed after their command prefix passes authorization. Pack contents are not inspected for file/path rules or commit ancestry.

Authorized Git requests look up repository metadata through the forge API to verify repository identity. These calls share the upstream credential's API rate limit; this release does not cache metadata or coordinate rate limits across deployments.

## Compatibility and verification scope

The automated tests cover real Git v2 discovery/clone/fetch, shallow and partial clones, known-hash reads, standard pushes, ref filtering, mixed denied pushes, tags, deletion, force updates, atomic and partial push outcomes, creation races/recovery, JWT tampering/expiry/size, secret/key reloads, identity substitution and malformed/gzip requests. Parser fuzz targets and race checks are included.

Supported object format is SHA-1. SSH, Git LFS, Git protocol v0/v1 fetch, signed push certificates, push options, named shallow exclusions, ref-in-want, offloaded pack/bundle URLs and provider-managed ref namespaces are rejected or not advertised. Branch writes can include workflow files; CI execution and secrets remain governed by the forge's configuration. GitHub branch rules continue to apply to the shared upstream identity.

No live GitHub credentials were required for the local suite. Validate the chosen account/token, organization creation policy, workflow permissions and GitHub Enterprise version in a disposable organization before deployment; the local API fixture cannot establish those external permissions.

The original requirements and implementation tradeoffs are in [the design](docs/git-proxy-design.md). [c2r](https://github.com/colony-2/c2r) informed the repository-provisioning approach. This implementation uses a small direct GitHub adapter; no c2r source was copied.

## Release automation

The [release workflow](.github/workflows/release.yaml) follows [c2j's release pattern](https://github.com/colony-2/c2j/blob/main/.github/workflows/release.yaml). Successful pushes to `main` in the `colony-2` organization run the test suite, automatically bump and push a version tag (patch by default), build four binaries, and publish GitHub release archives and checksums. It then publishes `@colony2/gitvend` to npm after installing and smoke-testing the packed wrapper against the published assets. There is no container-image build or publication.

GitHub release/tag publication uses the workflow's `GITHUB_TOKEN`. Configure npm trusted publishing for `colony-2/gitvend`, workflow `release.yaml`, or provide an `NPM_TOKEN` with publishing access to `@colony2/gitvend`. The npm package must exist and its trusted publisher must be configured before token-free publication can work; bootstrap it with a token if needed.

macOS signing/notarization is optional. Set all five secrets to enable it: `MACOS_SIGN_P12`, `MACOS_SIGN_PASSWORD`, `APPLE_API_ISSUER`, `APPLE_API_KEY_ID`, and `APPLE_API_KEY`. No signing secrets skips this step; a partial configuration fails the build. Signing requires the matching Apple certificate and notarization credentials.

The reusable [test workflow](.github/workflows/test.yml) runs Go race tests, vet, parser fuzzing and npm installer tests. Run the installer tests locally with `npm test --prefix npm/gitvend`. Release archive smoke tests also check all checksums and run the native binary's `version` command before upload.

Copied release tooling retains its upstream Apache-2.0 license and attribution in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This repository does not yet declare a project-wide license; npm metadata uses `UNLICENSED`.
