package main

const gatewaySetupHelp = `Give agents repository and branch access without sharing your GitHub token.
Gitvend verifies each agent's short-lived JWT and forwards authorized Git traffic
to GitHub using credentials configured on the gateway.

Setup:
  1. Install @colony2/gitvend with npm, or install a prebuilt release archive.
     Keep your GitHub token in the gateway's GITHUB_TOKEN environment variable.
     It needs access to the repositories you intend to serve.

  2. On the trusted issuer host, generate signing keys:

       mkdir -p var
       gitvend keygen --private var/signing.key --public var/signing.pub

     Keep signing.key with the issuer. Copy only signing.pub to the gateway.

  3. Save a gateway configuration as gitvend.yaml, adapting paths and owner names:

       listen: "0.0.0.0:8443"
       tls_cert: /run/secrets/gitvend.crt
       tls_key: /run/secrets/gitvend.key
       audience: gitvend
       keys:
         - id: orchestrator-1
           issuer: orchestrator
           public_key_file: var/signing.pub
           owners:
             github.com: [myorg]
       providers:
         - alias: github
           host: github.com
           kind: github
           git_base_url: https://github.com
           api_base_url: https://api.github.com
           allowed_owners: [myorg]
           credential:
             kind: token
             secret_ref: env:GITHUB_TOKEN
           allow_creation: false
           creation_defaults:
             visibility: private
             has_issues: false
             has_projects: false
             has_wiki: false
             has_pull_requests: false
       denies:
         - "!github.com/myorg/*#(main|master):wd"

     Configuration uses YAML. Unknown fields and duplicate keys fail
     validation. Relative gateway paths resolve from its working directory.
     For an HTTPS reverse proxy, use allow_http: true on a protected listener;
     agents must still use the proxy's public HTTPS endpoint.

  4. Check local configuration, then start the gateway:

       gitvend validate --config gitvend.yaml
       gitvend serve --config gitvend.yaml
       curl --fail https://git-gateway.example:8443/healthz

     Validation does not contact GitHub or check TLS certificates. /healthz checks
     liveness; an authenticated git ls-remote checks the actual Git access path.

  5. Issue a short-lived token on the trusted issuer host:

       gitvend sign --key var/signing.key --kid orchestrator-1 \
         --issuer orchestrator --subject agent-47 --ttl 15m \
         --permission 'github.com/myorg/project:r' \
         --permission 'github.com/myorg/project#agents/47/*:rw' \
         --output var/agent-47.jwt

     Deliver that JWT through your secret manager as /run/secrets/gitvend.jwt.
     JobDB users can automate issuance with jobdb-gitvend-secret-provider.

  6. In the agent's account, configure Git and use the gateway URL:

       git config --global protocol.version 2
       git config --global credential.https://git-gateway.example:8443.helper ''
       git config --global --add credential.https://git-gateway.example:8443.helper \
         '!gitvend credential --host git-gateway.example:8443 --token-file /run/secrets/gitvend.jwt'
       git ls-remote https://git-gateway.example:8443/github/myorg/project.git

Creation controls:
  To create missing repositories on first push, set allow_creation: true and
  grant c plus read/write access to at least one branch, for example
  github.com/myorg/cell-*:rwc. creation_defaults selects private/public visibility
  and GitHub features per upstream provider. GitHub credentials must authorize
  creation and any requested settings updates. Existing repositories keep their
  settings. A failed settings update blocks that push; inspect the created repo
  before retrying. Clone/fetch never creates a repository.

Use --help on any command for flags. Legacy single-dash long flags remain accepted.
Full guides: https://github.com/colony-2/gitvend/tree/main/docs
  gateway.md: installation, configuration, creation controls and troubleshooting
  jobdb-secret-provider.md: JobDB plugin and tenant permission configuration`
