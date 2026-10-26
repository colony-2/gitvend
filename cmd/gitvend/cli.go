package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/colony-2/gitvend/internal/auth"
	"github.com/colony-2/gitvend/internal/config"
	"github.com/colony-2/gitvend/internal/jsonutil"
	"github.com/colony-2/gitvend/internal/policy"
	"github.com/spf13/cobra"
)

func run(args []string, in io.Reader, out, errout io.Writer) error {
	root := newRootCmd()
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errout)
	root.SetArgs(legacyFlags(root, args))
	return root.Execute()
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use: "gitvend", Short: "Control GitHub access with short-lived agent credentials",
		Long: gatewaySetupHelp, Version: buildVersion(),
		SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	root.AddCommand(newServeCmd(), newValidateCmd(), newKeygenCmd(), newSignCmd(), newExplainCmd(), newCredentialCmd())
	root.AddCommand(&cobra.Command{Use: "version", Short: "Print the installed version", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "gitvend version", buildVersion())
			return err
		}})
	return root
}

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "serve", Short: "Start the Gitvend gateway", Args: cobra.NoArgs,
		Long:    "Start the gateway using YAML configuration. Run gitvend --help for setup.\nUse SIGHUP to reload configuration and keys; listener/TLS changes require a restart.",
		Example: "  gitvend serve --config gitvend.yaml"}
	path := cmd.Flags().StringP("config", "c", "gitvend.yaml", "Gateway configuration file (YAML)")
	_ = cmd.MarkFlagFilename("config", "yaml", "yml")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error { return serve(*path) }
	return cmd
}

func newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "validate", Short: "Validate gateway configuration, public keys and upstream credentials", Args: cobra.NoArgs,
		Long:    "Validate a YAML configuration and its local public-key/credential files.\nThis does not start the gateway or contact GitHub; TLS files are loaded when serving.",
		Example: "  gitvend validate --config gitvend.yaml"}
	path := cmd.Flags().StringP("config", "c", "gitvend.yaml", "Gateway configuration file (YAML)")
	_ = cmd.MarkFlagFilename("config", "yaml", "yml")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if _, err := config.Load(*path); err != nil {
			return err
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "Gateway configuration, public keys and credentials are valid.")
		return err
	}
	return cmd
}

func newCredentialCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "credential <get|store|erase>", Short: "Supply an agent JWT to Git's HTTPS credential helper", Args: cobra.ExactArgs(1),
		Long:    "Git invokes this helper with get, store, or erase. Only get returns a credential,\nand only for the configured gateway host. Use exactly one token source.",
		Example: "  git config --global --add credential.https://git-gateway.example.helper '!gitvend credential --host git-gateway.example --token-file /run/secrets/gitvend.jwt'"}
	f := cmd.Flags()
	host := f.String("host", "", "Exact gateway host[:port]")
	file := f.String("token-file", "", "Injected JWT file (read for each request)")
	env := f.String("token-env", "", "Injected JWT environment variable name")
	allowHTTP := f.Bool("allow-http", false, "Allow HTTP for local development")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return credential(*host, *file, *env, *allowHTTP, args[0], cmd.InOrStdin(), cmd.OutOrStdout())
	}
	return cmd
}

// Existing deployments and Git helpers use Go-style single-dash long flags.
// Normalize only recognized flags, never their values or arguments after --.
func legacyFlags(root *cobra.Command, args []string) []string {
	result := append([]string{}, args...)
	cmd := root
	start := 0
	if len(result) > 0 {
		for _, child := range root.Commands() {
			if result[0] == child.Name() {
				cmd, start = child, 1
				break
			}
		}
	}
	cmd.InitDefaultHelpFlag()
	for i := start; i < len(result); i++ {
		arg := result[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name, _, inline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		f := cmd.Flags().Lookup(name)
		if f == nil && len(name) == 1 {
			f = cmd.Flags().ShorthandLookup(name)
		}
		if f == nil {
			continue
		}
		if !strings.HasPrefix(arg, "--") && len(name) > 1 {
			result[i] = "-" + arg
		}
		if !inline && f.NoOptDefVal == "" {
			i++
		}
	}
	return result
}

func newKeygenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "keygen", Short: "Generate an Ed25519 signing-key pair", Args: cobra.NoArgs,
		Long:    "Generate a private issuer key and public gateway verification key. Keep the private\nkey with the issuer. Parent directories must exist; existing keys are not overwritten.",
		Example: "  gitvend keygen --private var/signing.key --public var/signing.pub"}
	f := cmd.Flags()
	private := f.String("private", "signing.key", "private key output (must not exist)")
	public := f.String("public", "signing.pub", "public key output (must not exist)")
	ifMissing := f.Bool("if-missing", false, "initialize persistent keys, reusing and validating existing keys")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		out := cmd.OutOrStdout()
		if *ifMissing {
			if e := ensureSigningKeys(*private, *public); e != nil {
				return e
			}
			fmt.Fprintln(out, "Signing keys ready")
			return nil
		}
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		privDER, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		pubDER, e := x509.MarshalPKIXPublicKey(pub)
		if e != nil {
			return e
		}
		for _, p := range []string{*private, *public} {
			if _, e = os.Stat(p); !os.IsNotExist(e) {
				return fmt.Errorf("key output already exists or is inaccessible: %s", p)
			}
		}
		if e = writeExclusive(*private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})); e != nil {
			return e
		}
		if e = writeExclusive(*public, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})); e != nil {
			return e
		}
		fmt.Fprintln(out, "Wrote", *private, "and", *public)
		return nil
	}
	return cmd
}

func newSignCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "sign", Short: "Issue a short-lived agent JWT", Args: cobra.NoArgs,
		Long:    "Sign an agent token using the trusted issuer's private key. The key ID, issuer and\naudience must match the gateway. Supply repeated --permission rules or a JSON --grant\nfile. --output writes an atomic private file; otherwise the token is printed to stdout.",
		Example: "  gitvend sign --key signing.key --kid jobdb --issuer jobdb --subject agent-47 --permission 'github.com/myorg/project:r' --output agent.jwt"}
	f := cmd.Flags()
	keyPath := f.String("key", "", "private key PEM")
	kid := f.String("kid", "", "configured key ID")
	issuer := f.String("issuer", "", "configured issuer")
	subject := f.String("subject", "", "agent/task identity")
	aud := f.String("audience", "gitvend", "service audience")
	ttl := f.Duration("ttl", 15*time.Minute, "token lifetime")
	max := f.Int("max-token-bytes", 4096, "serialized JWT budget")
	grantPath := f.String("grant", "", "JSON grant file (v, permissions)")
	output := f.String("output", "", "atomic token file output; default stdout")
	revision := f.String("policy-revision", "", "issuer revision for audit")
	perms := f.StringArray("permission", nil, "Permission rule (repeat for multiple rules)")
	for _, name := range []string{"key", "kid", "issuer", "subject"} {
		_ = cmd.MarkFlagRequired(name)
	}
	cmd.MarkFlagsMutuallyExclusive("permission", "grant")
	cmd.MarkFlagsOneRequired("permission", "grant")
	_ = cmd.MarkFlagFilename("key")
	_ = cmd.MarkFlagFilename("grant", "json")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		out := cmd.OutOrStdout()
		if *keyPath == "" || *kid == "" || *issuer == "" || *subject == "" || *aud == "" || *ttl <= 0 || *ttl > 24*time.Hour || *max < 512 || *max > 32768 {
			return fmt.Errorf("key, kid, issuer, subject and valid lifetime/size required")
		}
		grant := auth.Grant{Version: 1, Permissions: *perms}
		if *grantPath != "" {
			if len(*perms) > 0 {
				return fmt.Errorf("use grant file or permissions, not both")
			}
			b, e := os.ReadFile(*grantPath)
			if e != nil {
				return e
			}
			if e = jsonutil.Decode(b, &grant); e != nil {
				return e
			}
		}
		if grant.Version != 1 {
			return fmt.Errorf("unsupported grant version")
		}
		b, e := os.ReadFile(*keyPath)
		if e != nil {
			return e
		}
		key, e := auth.ParsePrivate(b)
		if e != nil {
			return e
		}
		claims := auth.NewClaims(*issuer, *subject, *aud, *ttl, grant)
		claims.PolicyRevision = *revision
		token, e := auth.Sign(claims, key, *kid, *max)
		if e != nil {
			return e
		}
		if *output != "" {
			return writeAtomic(*output, []byte(token+"\n"))
		}
		_, e = fmt.Fprintln(out, token)
		return e
	}
	return cmd
}

func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "explain", Short: "Explain repository and branch permissions", Args: cobra.NoArgs,
		Long:    "Evaluate explicit permission rules without contacting GitHub. This does not load\ngateway configuration or validate upstream permissions. Inspect the JSON allowed field;\na denied decision is still a successful explanation command.",
		Example: "  gitvend explain --repo github.com/myorg/cell --action repo.create --permission 'github.com/myorg/*:rwc'"}
	f := cmd.Flags()
	repo := f.String("repo", "", "host/namespace/repo")
	ref := f.String("ref", "", "fully qualified ref")
	action := f.String("action", "ref.update", "repo.read, repo.create, ref.discover, ref.create, ref.update or ref.delete")
	perms := f.StringArray("permission", nil, "Permission rule (repeat for multiple rules)")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		out := cmd.OutOrStdout()
		host, path, ok := strings.Cut(*repo, "/")
		if !ok {
			return fmt.Errorf("repo must be host/namespace/repository")
		}
		p, e := policy.Compile(*perms)
		if e != nil {
			return e
		}
		r := policy.Repository{Host: host, Path: strings.ToLower(path), FoldCase: true}
		d := p.Explain(r, *ref, *action)
		allowed := d.Allowed
		switch *action {
		case "repo.read", "repo.create":
		case "ref.discover":
			allowed = p.Discover(r, *ref)
		case "ref.create", "ref.update", "ref.delete":
			allowed = p.Write(r, *ref, *action)
		default:
			return fmt.Errorf("unknown action")
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"allowed": allowed, "action": d, "repository_read": p.Explain(r, "", "repo.read"), "discovery": p.Explain(r, *ref, "ref.discover")})
	}
	return cmd
}
