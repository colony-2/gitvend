package cmd

const setupHelp = `Issue tenant read and target-cell write JWTs for jobs with verified lease authority.
JobDB launches this executable with --config using its secret-provider plugin SDK.
Use validate to check your setup before starting JobDB.

Setup:
  1. Generate an Ed25519 signing-key pair using the gitvend CLI:

       mkdir -p .dev-secrets
       gitvend keygen -private .dev-secrets/signing.key -public .dev-secrets/signing.pub

  2. Save an issuer configuration as .dev-secrets/gitvend-issuer.json, adapting
     the tenant name and repository patterns to your deployment:

       {
         "issuer": "jobdb",
         "audience": "gitvend",
         "key_id": "jobdb",
         "signing_key_file": "signing.key",
         "tenants": {
           "example": {
             "read_permissions": ["github.com/example-org/*:r"],
             "cell_write_repositories": ["github.com/example-org/cell-*"]
           }
         }
       }

     The signing-key path is relative to the issuer file. Keep the private key
     with this provider. Configure the Gitvend gateway with signing.pub, key ID
     "jobdb", issuer "jobdb", audience "gitvend", and matching owner ceilings
     and upstream routes. The gateway holds its upstream GitHub token separately.

     github.com/*:r permits all reads available through those upstream credentials;
     it does not isolate private repositories between tenants. Use narrower read
     patterns when tenants need different read scopes.

  3. Validate the issuer configuration and key:

       jobdb-gitvend-secret-provider validate --config .dev-secrets/gitvend-issuer.json

  4. Save a JobDB providers.json using absolute paths for the executable and config:

       {
         "version": 1,
         "providers": [{
           "id": "gitvend",
           "type": "plugin",
           "command": "/absolute/path/to/jobdb-gitvend-secret-provider",
           "args": ["--config", "/absolute/path/to/.dev-secrets/gitvend-issuer.json"]
         }]
       }

     Start JobDB with its provider configuration:

       jobdb sqlite --db ./jobdb.db --secret-providers-file /absolute/path/to/providers.json

  5. Jobs request gitvend_read_token or gitvend_cell_token. The latter adds writes
     to the repository in AppMetadata.repo (configurable via cell_metadata_field),
     checked against the tenant's cell_write_repositories patterns. For example:

       {"repo":"https://github.com/example-org/cell-one.git"}

     Workers use the JWT as the HTTP Basic password for the Gitvend gateway's
     repository URL. Fetches use Git protocol v2. Tokens expire within verified
     lease authority; match gateway_leeway_seconds (default 30) to the gateway.

Config and signing-key changes reload automatically. Invalid replacements retain
the last valid configuration and retry. Already issued JWTs keep their original
permissions until expiry; use JobDB fresh secret resolution for updated tokens.

Full documentation: docs/jobdb-secret-provider.md in the Gitvend repository.`

const commandExamples = `  # Show setup instructions (no configuration or JobDB process required)
  jobdb-gitvend-secret-provider --help

  # Check configuration before registering the plugin in JobDB
  jobdb-gitvend-secret-provider validate --config /absolute/path/gitvend-issuer.json

  # JobDB launches the plugin with this command; stdout carries its handshake
  jobdb-gitvend-secret-provider --config /absolute/path/gitvend-issuer.json`
