# Gitvend secret-provider plugin for JobDB

This executable implements `jobdb.SecretProvider` and serves it through JobDB's
`secretplugin.Serve` SDK. JobDB starts it as a local subprocess using the SDK's
authenticated gRPC protocol. It signs credentials locally with an Ed25519 key;
the Gitvend gateway needs only the matching public key. No GitHub token is sent
to JobDB or the worker by this plugin.

It returns only requested, authorized secret names:

| Secret name | JWT permissions |
| --- | --- |
| `gitvend_read_token` | The configured tenant read permissions. |
| `gitvend_cell_token` | The same reads plus `rw` for the exact target cell repository. |

These are signed JWT **tokens**, not signing keys. The cell token permits branch
and tag creation/update within an existing repository; it does not grant ref
deletion (`d`) or repository creation (`c`). Tenant read denies and gateway denies
still apply. A read-only request does not need cell metadata.

## Build and configure

From the Gitvend checkout:

```sh
make build build-jobdb-provider
mkdir -p .dev-secrets
bin/gitvend keygen -private .dev-secrets/signing.key -public .dev-secrets/signing.pub
cp plugins/jobdb/issuer.example.json .dev-secrets/gitvend-issuer.json
```

Edit the issuer file for your tenant names and permitted cell repositories.
`signing_key_file` resolves relative to that file. Protect the private key and
keep it in the provider process; configure Gitvend with the public key. The
issuer, audience and key ID must match Gitvend's trusted-key configuration.
The gateway's key owner ceiling and upstream owner routes must cover the intended
repositories. Configure its upstream GitHub credential separately as usual.

Example policy for more restricted reads:

```json
{
  "read_permissions": [
    "github.com/public-org/*:r",
    "github.com/example-org/shared-library:r"
  ],
  "cell_write_repositories": ["github.com/example-org/cell-*"],
  "principals": ["trusted-job-submitter"]
}
```

`read_permissions` accepts Gitvend permission syntax with only the `r` action,
including read denies. `cell_write_repositories` accepts repository patterns
without actions, ref selectors, denies, or `.git` suffixes. An empty/omitted list
disables the cell token for that tenant. Optional `principals` restricts both
tokens to those exact broker-verified principals; omitting it authorizes all
principals, including absent principals, within that configured tenant.

Configure JobDB with a provider file, using absolute paths:

```json
{
  "version": 1,
  "providers": [
    {
      "id": "gitvend",
      "type": "plugin",
      "command": "/absolute/path/to/gitvend/bin/jobdb-gitvend-secret-provider",
      "args": ["--config", "/absolute/path/to/gitvend/.dev-secrets/gitvend-issuer.json"]
    }
  ]
}
```

```sh
jobdb sqlite --db ./jobdb.db --secret-providers-file /absolute/path/to/providers.json
```

The JobDB version must include the secret-provider plugin SDK. This module pins
the SDK commit used for testing. Other providers, including SQLite, can coexist
in the same provider file; the first entry for each secret name wins. See
[the provider guide](https://github.com/colony-2/jobdb/blob/f403447cb58a7195e32a55fb7f417e09da70f388/docs/GUIDE-SECRET-PROVIDERS.md) for collection behavior.
An omission here cannot veto a grant from a different provider.

The worker requests either or both names through JobDB's normal secret-resolution
API and uses the returned JWT as the Gitvend HTTP Basic password. It still uses
the gateway's Git URL, for example
`https://gitvend.example/github/example-org/cell-one.git`, with Git protocol v2.

## Cell metadata and authorization

The default `cell_metadata_field` is `repo`, matching c2j's target repository
metadata. It is a top-level field in `SecretResolveRequest.AppMetadata`, e.g.:

```json
{
  "cell_id": "cell-123",
  "cell_name": "cell-one",
  "repo": "https://github.com/example-org/cell-one.git"
}
```

Accepted repository forms are `https://host/owner/repo[.git]` and
`host/owner/repo[.git]`. Owner/repository casing is normalized. Credentials, query
strings, fragments, encoded paths, extra path segments and permission syntax are
rejected. Configure a different field if your application uses another name;
its value must still identify a repository, not an opaque cell ID. SSH URLs and
cell-ID-to-repository lookups are not implemented.

The provider matches that repository against the **verified tenant's** configured
cell write patterns, then adds only the exact repository to the cell JWT.
Missing, malformed or unauthorized metadata omits the cell token while leaving
an independently authorized read token available. Unknown names and tenants are
also omitted.

Application metadata may be submitter-controlled. The configured write patterns
are an authorization ceiling: authorized jobs in that tenant may select any
matching cell. If individual jobs or principals must be confined to different
cells within a tenant, a trusted job/principal-to-cell authorization lookup is
needed before widening this model. Metadata by itself does not establish such
a binding. `cell_id` and `cell_name` do not override `repo`.

## Private repository reads

The initial implementation deliberately does not discover GitHub visibility or
user membership. `github.com/*:r` authorizes reads across the host, intersected
with Gitvend's signing-key owner ceiling, gateway routes/denies, and the actual
upstream GitHub token's permissions. Permission strings use `github.com`, not
the route alias `github`.

This broad setting works when all tenants receiving it are allowed to read
everything available to those Gitvend upstream credentials. The upstream token
cannot provide tenant-specific isolation: Gitvend selects it by provider route,
not by the JobDB tenant or principal. With a shared upstream token, a tenant can
read other tenants' private repositories if all those checks permit them.

For different tenant read scopes, configure explicit tenant read patterns. For
credential-level separation, use separate gateway deployments/credentials or
non-overlapping owner routes and key ceilings as appropriate. A pattern does
not mean “public repositories only”: matching private repositories are readable
if the upstream token allows them. Visibility-aware authorization remains outside
this first version.

## Lifetime and operation

The signed expiry and returned `SecretValue.ExpiresAt` are identical, and
`LeaseBound` is true. The provider uses the earlier of `AuthorizedNotAfter` and
`LeaseExpiresAt`, subtracts gateway leeway and the clock margin, and rounds down
to a whole second. It also caps the encoded lifetime at `max_lifetime_seconds`.
Defaults are 900 seconds, 30 seconds of gateway leeway, a 1-second clock margin,
and a 4096-byte token limit. Match these settings to the gateway; the provider
cannot discover its configuration. Set the margin for your actual clock skew.

Missing verified job/lease identity or deadlines fails issuance. Too little
remaining lifetime returns `ErrSecretsUnavailable`. The request context bounds
resolution work, not token lifetime. Backend renewal cannot extend a token minted
through an older presenting capability; obtain a renewed handle and use JobDB's
fresh secret resolution to refresh credentials. Already delivered JWTs remain
valid until their expiry plus gateway leeway even if the job is canceled earlier.

There is no token cache. Every resolution issues fresh token IDs. The audit
subject is `jobdb:` followed by the SHA-256 digest of the JSON array
`[tenantID, jobID, leaseID, workerID, principal]`; absent principal is JSON `null`.
This binds audit identity to the lease attempt within Gitvend's subject length
limit. `policy_revision` is copied into the JWT for gateway auditing.

Configuration and the referenced signing-key file reload automatically using
fsnotify on Linux and macOS. The plugin watches their parent directories so
atomic file replacements continue to be detected. Changes are debounced for
100 milliseconds, then a fresh configuration and key are fully validated before
being published together. Each request captures one complete snapshot; an
in-flight request finishes with its original policy and key, while new requests
use the replacement. Removed tenants and permissions are removed on reload.

A malformed, missing or unreadable replacement leaves the last valid snapshot
active. The plugin reports a fixed error message and retries every second until
loading succeeds, including when a new signing-key path does not exist yet.
Startup still requires valid files and working directory watches. Changing the
key path updates the watches after a successful reload. For coordinated key
rotation, write a new key file first, then atomically replace the config with its
new path and key ID; provision the corresponding gateway public key beforehand.

Reloading does not revoke already issued JWTs or replace credentials cached by
JobDB workflows. Use fresh secret resolution to obtain updated permissions.
Diagnostics go to stderr without keys, JWTs, raw configuration, or raw errors;
the JobDB host may suppress plugin output. Watching uses local filesystem events,
with no periodic polling after successful loads. Network filesystems and changes
to symlink targets outside the watched directories require a different update
mechanism or restarting the plugin host.

## Development

```sh
make check-jobdb-provider
```

Tests verify grants and effective expiry with Gitvend's actual verifier, tenant
and principal checks, metadata injection rejection, concurrent reloads, key
rotation, invalid-file recovery, and the built executable's real JobDB plugin
handshake and live reload. The separate Go module keeps the JobDB
SDK dependencies out of the gateway module. Build this plugin from the checkout;
its local Gitvend module replacement intentionally uses the same signing and
permission implementation as that checkout's gateway.
