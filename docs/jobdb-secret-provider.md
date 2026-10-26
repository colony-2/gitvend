# Gitvend secret-provider plugin for JobDB

The JobDB plugin gives workers short-lived Gitvend credentials for their jobs.
You configure permissions per tenant and additional permissions for the target
cell repository. JobDB starts the plugin when needed and passes verified job and
lease information. The plugin signs tokens locally; the gateway needs only the
matching public key. Workers never receive the GitHub token or private signing key.

Set up a [Gitvend gateway](gateway.md) first, or configure it alongside the plugin.
The plugin runs on the JobDB host; it does not replace the gateway.
It returns only requested, authorized secret names:

| Secret name | JWT permissions |
| --- | --- |
| `gitvend_base_token` | The configured tenant `base_permissions`, unchanged. |
| `gitvend_cell_token` | Base permissions plus matching `target_permissions`, narrowed to the exact target cell repository. |

These are signed JWT **tokens**, not signing keys. Both lists accept the standard
[Gitvend permission syntax](permission-syntax.md), including `r`, `w`, `d`, `c`,
ref selectors, and denies. A base-token request does not need cell metadata.
Matching denies still win across both lists and the gateway's deny rules.

## Install

On the host where JobDB runs, install the package:

```sh
npm install -g @colony2/gitvend
jobdb-gitvend-secret-provider --help
```

The package supplies prebuilt `gitvend` and `jobdb-gitvend-secret-provider`
executables for Linux/macOS on amd64/arm64. npm requires Node.js 22+, `tar`, and
enabled install scripts. For installation without Node.js, download a
[release archive](https://github.com/colony-2/gitvend/releases) containing both
executables, verify its checksum, and put them on `PATH`. Older releases may
contain only the gateway; use a release that includes the plugin.

The npm installer places a native executable at the plugin command path, so
JobDB does not need Node.js or `PATH` in the plugin environment.

Use a JobDB version with secret-provider plugin support. JobDB must be able to
execute the installed command and read the issuer configuration and signing key.

## Configure the issuer

Configuration uses YAML. Unknown fields, duplicate keys and multiple documents
are rejected. JSON-shaped mappings also load as YAML.

Generate a signing key on the trusted JobDB host:

```sh
mkdir -p gitvend-issuer
gitvend keygen --private gitvend-issuer/signing.key --public gitvend-issuer/signing.pub
```

Save this as `gitvend-issuer/issuer.yaml`, replacing `YOUR_TENANT_ID` with the
actual JobDB tenant ID:

```yaml
issuer: jobdb
audience: gitvend
key_id: jobdb
signing_key_file: signing.key
cell_metadata_field: repo
tenants:
  YOUR_TENANT_ID:
    base_permissions:
      - github.com/*:r
    target_permissions:
      - github.com/colony-2/*:rwc
```

This permits all GitHub reads available through the gateway, plus read/write/create
on the target cell under `colony-2`. Use narrower base rules when tenants must not
share private repository access. The [complete issuer example](../examples/jobdb-gitvend-issuer.yaml)
also shows token lifetime and size settings.

`signing_key_file` resolves relative to the issuer file. Keep the private key on
the JobDB host and copy only `signing.pub` to the gateway. Add a gateway `keys`
entry with ID `jobdb`, issuer `jobdb`, and the public key's path. Its owner
allowlist and the upstream provider's allowed owners must cover the repositories
in your policy. The audience must also match. Configure upstream GitHub credentials
on the gateway separately.

Validate before registering the plugin:

```sh
jobdb-gitvend-secret-provider validate --config gitvend-issuer/issuer.yaml
```

Expected output: `Configuration and signing key are valid.` This checks the local
configuration and private key; it does not test GitHub access or gateway connectivity.

## Tenant permissions

Example policy for more restricted reads:

```yaml
base_permissions:
  - github.com/public-org/*:r
  - github.com/example-org/shared-library:r
target_permissions:
  - github.com/example-org/cell-*:rwc
principals:
  - trusted-job-submitter
```

`base_permissions` applies to both tokens, including the target repository.
`target_permissions` grants additional authority only for the repository selected
by metadata. For example, this tenant policy allows all accessible GitHub reads
and read/write/create on the target cell if it belongs to `colony-2`:

```yaml
base_permissions:
  - github.com/*:r
target_permissions:
  - github.com/colony-2/*:rwc
```

For `AppMetadata.repo = "https://github.com/colony-2/my-cell.git"`, the cell JWT
contains `github.com/*:r` and `github.com/colony-2/my-cell:rwc`. It does not grant
writes or creation to any other cell. A target rule such as
`github.com/colony-2/*#work/*:rw` retains its branch selector after narrowing.
Use a separate repository-wide `:c` rule for creation when writes are branch-scoped;
Gitvend rejects `c` with a ref selector.

An empty/omitted base list disables the base token. An empty/omitted target list,
or no matching target allow rule, disables the cell token. A tenant must have
at least one rule, with at most 128 rules across both lists. Optional `principals`
restricts both tokens to those exact broker-verified principals; omitting it
authorizes all principals, including absent principals, within that tenant.

Creation still requires the gateway provider's `allow_creation: true` and a
readable/writable branch. Its `creation_defaults` chooses visibility and GitHub
features; the issuer cannot override those defaults. See
[gateway creation settings](gateway.md#repository-creation-defaults).

### Migrating the original issuer config

Rename `read_permissions` to `base_permissions`. Replace `cell_write_repositories`
with `target_permissions`, adding `:rw` to each old repository pattern to preserve
its permissions, or `:rwc` to also allow creation. Update workers to request
`gitvend_base_token` instead of `gitvend_read_token`; `gitvend_cell_token` is unchanged.
Old config fields are rejected, and the old secret name is omitted rather than
silently returning a token that may now carry write permissions. Deploy the
new config and executable together; validate the config before restarting JobDB's
plugin process.

## Register with JobDB

Find the installed command with `command -v jobdb-gitvend-secret-provider`.
Save a `providers.json` file using absolute paths for that executable and your
issuer configuration:

```json
{
  "version": 1,
  "providers": [
    {
      "id": "gitvend",
      "type": "plugin",
      "command": "/absolute/path/to/jobdb-gitvend-secret-provider",
      "args": ["--config", "/absolute/path/to/gitvend-issuer/issuer.yaml"]
    }
  ]
}
```

```sh
jobdb sqlite --db ./jobdb.db --secret-providers-file /absolute/path/to/providers.json
```

Other providers, including SQLite, can coexist in the same provider file; the first entry for each secret name wins. See
[the provider guide](https://github.com/colony-2/jobdb/blob/f403447cb58a7195e32a55fb7f417e09da70f388/docs/GUIDE-SECRET-PROVIDERS.md) for collection behavior.
An omission here cannot veto a grant from a different provider.

The worker requests either or both names through JobDB's normal secret-resolution
API and uses the returned JWT as the Gitvend HTTP Basic password. It still uses
the gateway's Git URL, for example
`https://gitvend.example/github/example-org/cell-one.git`, with Git protocol v2.
Follow the [agent authentication instructions](gateway.md#configure-git-authentication)
to configure the Git credential helper.

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
target rules, then replaces each matching rule's repository pattern with the
exact repository while preserving its actions, ref selector and deny flag.
Missing, malformed or unauthorized metadata omits the cell token while leaving
an independently authorized base token available. Unknown names and tenants are
also omitted.

Application metadata may be submitter-controlled. The configured target patterns
are an authorization ceiling: authorized jobs in that tenant may select any
matching cell. If individual jobs or principals must be confined to different
cells within a tenant, a trusted job/principal-to-cell authorization lookup is
needed before widening this model. Metadata by itself does not establish such
a binding. `cell_id` and `cell_name` do not override `repo`.

## Private repository reads

The plugin does not discover GitHub visibility or user membership. `github.com/*:r` authorizes reads across the host, intersected
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
if the upstream token allows them. The plugin has no “public repositories only” permission option.

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

Every resolution issues fresh tokens. `policy_revision` is included for gateway
auditing; the audit subject identifies the tenant/job/lease context without
exposing the raw identifiers.

## Configuration reloads and key rotation

Configuration and signing-key changes reload automatically on Linux and macOS,
including atomic file replacements. A request uses one complete configuration
and key snapshot; subsequent requests use the replacement after validation.
Removed tenants and permissions affect newly issued tokens.

A malformed, missing or unreadable replacement leaves the last valid snapshot
active. The plugin reports a fixed error message and retries every second until
loading succeeds, including when a new signing-key path does not exist yet.
Startup still requires valid files and access to watch their directories. For coordinated key
rotation, write a new key file first, then atomically replace the config with its
new path and key ID; provision the corresponding gateway public key beforehand.

Reloading does not revoke already issued JWTs or replace credentials cached by
JobDB workflows. Use fresh secret resolution to obtain updated permissions.
Diagnostics go to stderr without keys, JWTs, raw configuration, or raw errors;
the JobDB host may suppress plugin output. Watching uses local filesystem events,
with no periodic polling after successful loads. Network filesystems and changes
to symlink targets outside the watched directories require a different update
mechanism or restarting the plugin host.

## Command reference

| Command | Purpose |
| --- | --- |
| `jobdb-gitvend-secret-provider --help` | Show setup instructions. |
| `jobdb-gitvend-secret-provider validate --config issuer.yaml` | Validate local configuration and the signing key. |
| `jobdb-gitvend-secret-provider --config issuer.yaml` | Invocation registered with JobDB; JobDB launches this process. |
| `jobdb-gitvend-secret-provider version` | Show the installed version. |
| `jobdb-gitvend-secret-provider completion --help` | Set up shell completion. |

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Command is missing after npm install | Use a release that includes the plugin, check `PATH`, and ensure npm install scripts ran. After fixing download/install-script errors, run `npm rebuild @colony2/gitvend`. |
| Configuration validation fails | Check YAML field names, permission syntax, tenant IDs, and the signing-key path relative to the issuer file. |
| Neither token is returned | Check the verified tenant/principal, requested secret names, and job lease authority. Unknown names and unauthorized tenants are omitted. |
| Base token works but cell token is missing | Check `AppMetadata.repo`, `cell_metadata_field`, and whether a target allow rule matches that exact repository. |
| Gateway rejects a token | Check issuer, key ID, audience, signing key, clock tolerance, lifetime limits, and gateway owner allowlists. |
| Cell push cannot create a repository | The target rules need `c` plus a readable/writable branch. Check the gateway's `allow_creation`, upstream permissions, and creation settings. |
| Config changed but a worker still has old permissions | Obtain fresh secrets through JobDB. Already issued JWTs retain their permissions until expiry, and invalid replacements leave the last valid config active. |

For source builds, tests, or SDK integration, see the [developer guide](development.md).
