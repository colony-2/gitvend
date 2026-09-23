package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/colony-2/gitvend/internal/jsonutil"
	"github.com/colony-2/gitvend/internal/policy"
	"github.com/golang-jwt/jwt/v5"
)

const Type = "gitvend+jwt"

type Grant struct {
	Version     int      `json:"v"`
	Permissions []string `json:"permissions"`
}
type Claims struct {
	jwt.RegisteredClaims
	Grant          Grant  `json:"grant"`
	PolicyRevision string `json:"policy_revision,omitempty"`
}
type Key struct {
	Issuer string
	Public ed25519.PublicKey
	Owners map[string][]string
}
type Verifier struct {
	Audience            string
	Keys                map[string]Key
	MaxBytes            int
	MaxLifetime, Leeway time.Duration
	Now                 func() time.Time
	Denies              []string
}
type Identity struct {
	Claims *Claims
	Policy *policy.Policy
	Key    Key
	Kid    string
	Expiry time.Time
}

func (i *Identity) Access(repo policy.Repository) bool {
	owners := i.Key.Owners[repo.Host]
	at := strings.LastIndexByte(repo.Path, '/')
	if at < 0 {
		return false
	}
	owner := repo.Path[:at]
	for _, o := range owners {
		if o == owner || repo.FoldCase && strings.EqualFold(o, owner) {
			return true
		}
	}
	return false
}
func (v *Verifier) Verify(raw string) (*Identity, error) {
	if v.MaxBytes <= 0 || len(raw) > v.MaxBytes {
		return nil, fmt.Errorf("token too large")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT")
	}
	hb, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return nil, e
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if e = jsonutil.Decode(hb, &header); e != nil {
		return nil, e
	}
	if header.Alg != "EdDSA" || header.Typ != Type {
		return nil, fmt.Errorf("unsupported JWT profile")
	}
	key, ok := v.Keys[header.Kid]
	if !ok {
		return nil, fmt.Errorf("unknown signing key")
	}
	pb, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return nil, e
	}
	claims := new(Claims)
	if e = jsonutil.Decode(pb, claims); e != nil {
		return nil, e
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	_, e = jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) { return key.Public, nil }, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(key.Issuer), jwt.WithAudience(v.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(v.Leeway), jwt.WithTimeFunc(now), jwt.WithStrictDecoding())
	if e != nil {
		return nil, e
	}
	if claims.Subject == "" || len(claims.Subject) > 256 || claims.ID == "" || len(claims.ID) > 128 || claims.IssuedAt == nil || claims.NotBefore == nil || len(claims.Audience) != 1 || claims.Audience[0] != v.Audience || claims.Grant.Version != 1 {
		return nil, fmt.Errorf("missing or invalid claims")
	}
	if claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) > v.MaxLifetime || !claims.ExpiresAt.After(claims.IssuedAt.Time) || claims.NotBefore.After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("invalid token lifetime")
	}
	lines := append([]string(nil), claims.Grant.Permissions...)
	lines = append(lines, v.Denies...)
	p, e := policy.Compile(lines)
	if e != nil {
		return nil, e
	}
	return &Identity{Claims: claims, Policy: p, Key: key, Kid: header.Kid, Expiry: claims.ExpiresAt.Time.Add(v.Leeway)}, nil
}
func Sign(claims *Claims, key ed25519.PrivateKey, kid string, maxBytes int) (string, error) {
	if _, e := policy.Compile(claims.Grant.Permissions); e != nil {
		return "", e
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["typ"] = Type
	t.Header["kid"] = kid
	s, e := t.SignedString(key)
	if e == nil && len(s) > maxBytes {
		return "", fmt.Errorf("JWT is %d bytes, exceeds %d-byte budget", len(s), maxBytes)
	}
	return s, e
}
func NewClaims(issuer, subject, audience string, ttl time.Duration, grant Grant) *Claims {
	now := time.Now().UTC()
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return &Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: subject, Audience: jwt.ClaimStrings{audience}, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(ttl)), ID: hex.EncodeToString(b)}, Grant: grant}
}
func ParsePublic(b []byte) (ed25519.PublicKey, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, fmt.Errorf("expected public key PEM")
	}
	k, e := x509.ParsePKIXPublicKey(p.Bytes)
	if e != nil {
		return nil, e
	}
	ed, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected Ed25519 public key")
	}
	return ed, nil
}
func ParsePrivate(b []byte) (ed25519.PrivateKey, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, fmt.Errorf("expected private key PEM")
	}
	k, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return nil, e
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected Ed25519 private key")
	}
	return ed, nil
}
