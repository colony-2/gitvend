package gitwire

import (
	"bytes"
	"fmt"
	"github.com/colony-2/gitgate/internal/policy"
	"io"
	"strconv"
	"strings"
)

type Update struct {
	Old    string `json:"old"`
	New    string `json:"new"`
	Ref    string `json:"ref"`
	Action string `json:"action"`
}
type Push struct {
	Prefix       []byte
	Updates      []Update
	Capabilities []string
}

func OID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func Zero(s string) bool { return s == strings.Repeat("0", 40) }
func pushCap(s string) bool {
	switch s {
	case "report-status", "report-status-v2", "side-band-64k", "ofs-delta", "atomic", "delete-refs", "quiet", "object-format=sha1":
		return true
	}
	return strings.HasPrefix(s, "agent=") && len(s) < 256
}
func ParsePush(r io.Reader, maxBytes, maxRefs int) (Push, error) {
	out := Push{}
	var b bytes.Buffer
	seen := map[string]bool{}
	for {
		p, e := Read(r)
		if e != nil {
			return out, e
		}
		b.Write(Encode(p))
		if b.Len() > maxBytes {
			return out, fmt.Errorf("push command section too large")
		}
		if p.Kind == 0 {
			break
		}
		if p.Kind != 3 {
			return out, fmt.Errorf("invalid push framing")
		}
		line := strings.TrimSuffix(string(p.Data), "\n")
		if strings.ContainsAny(line, "\r\n") {
			return out, fmt.Errorf("invalid command")
		}
		if left, right, ok := strings.Cut(line, "\x00"); ok {
			if len(out.Updates) != 0 || strings.ContainsRune(right, 0) {
				return out, fmt.Errorf("invalid capability position")
			}
			line = left
			out.Capabilities = strings.Fields(right)
			for _, cap := range out.Capabilities {
				if !pushCap(cap) {
					return out, fmt.Errorf("unsupported push capability")
				}
			}
		}
		fields := strings.Split(line, " ")
		if len(fields) != 3 || !OID(fields[0]) || !OID(fields[1]) || !policy.ValidRef(fields[2]) || seen[fields[2]] {
			return out, fmt.Errorf("invalid or duplicate ref command")
		}
		seen[fields[2]] = true
		u := Update{Old: fields[0], New: fields[1], Ref: fields[2], Action: "ref.update"}
		if Zero(u.Old) {
			u.Action = "ref.create"
		}
		if Zero(u.New) {
			u.Action = "ref.delete"
		}
		if Zero(u.Old) && Zero(u.New) {
			return out, fmt.Errorf("both object IDs are zero")
		}
		out.Updates = append(out.Updates, u)
		if len(out.Updates) > maxRefs {
			return out, fmt.Errorf("too many ref commands")
		}
	}
	if len(out.Updates) == 0 {
		return out, fmt.Errorf("empty push")
	}
	out.Prefix = b.Bytes()
	return out, nil
}

type Fetch struct {
	Command  string
	Prefixes []string
}

func ParseFetch(b []byte) (Fetch, error) {
	out := Fetch{}
	r := bytes.NewReader(b)
	args := false
	count := 0
	for {
		p, e := Read(r)
		if e != nil {
			return out, e
		}
		if p.Kind == 0 {
			if r.Len() != 0 {
				return out, fmt.Errorf("trailing request data")
			}
			break
		}
		if p.Kind == 1 {
			if args || out.Command == "" {
				return out, fmt.Errorf("invalid delimiter")
			}
			args = true
			continue
		}
		if p.Kind != 3 {
			return out, fmt.Errorf("invalid framing")
		}
		s := strings.TrimSuffix(string(p.Data), "\n")
		if strings.ContainsAny(s, "\x00\r\n") {
			return out, fmt.Errorf("invalid argument")
		}
		count++
		if count > 32768 {
			return out, fmt.Errorf("too many arguments")
		}
		if !args {
			if strings.HasPrefix(s, "command=") {
				if out.Command != "" {
					return out, fmt.Errorf("multiple commands")
				}
				out.Command = strings.TrimPrefix(s, "command=")
				if out.Command != "ls-refs" && out.Command != "fetch" {
					return out, fmt.Errorf("unsupported command")
				}
			} else if !(strings.HasPrefix(s, "agent=") && len(s) < 256 || s == "object-format=sha1") {
				return out, fmt.Errorf("unsupported capability")
			}
			continue
		}
		if out.Command == "ls-refs" {
			switch {
			case s == "symrefs", s == "peel", s == "unborn":
			case strings.HasPrefix(s, "ref-prefix "):
				prefix := strings.TrimPrefix(s, "ref-prefix ")
				if len(prefix) > 1024 {
					return out, fmt.Errorf("prefix too long")
				}
				out.Prefixes = append(out.Prefixes, prefix)
			default:
				return out, fmt.Errorf("unsupported ls-refs argument")
			}
			continue
		}
		switch {
		case s == "done", s == "thin-pack", s == "no-progress", s == "include-tag", s == "ofs-delta", s == "deepen-relative", s == "wait-for-done":
		case strings.HasPrefix(s, "want "), strings.HasPrefix(s, "have "), strings.HasPrefix(s, "shallow "):
			_, id, _ := strings.Cut(s, " ")
			if !OID(id) {
				return out, fmt.Errorf("invalid object ID")
			}
		case strings.HasPrefix(s, "deepen "), strings.HasPrefix(s, "deepen-since "):
			_, v, _ := strings.Cut(s, " ")
			n, e := strconv.ParseUint(v, 10, 63)
			if e != nil || n == 0 {
				return out, fmt.Errorf("invalid depth")
			}
		case s == "filter blob:none":
		case strings.HasPrefix(s, "filter blob:limit="):
			if _, e := strconv.ParseUint(strings.TrimPrefix(s, "filter blob:limit="), 10, 63); e != nil {
				return out, fmt.Errorf("invalid filter")
			}
		case strings.HasPrefix(s, "filter tree:"):
			if _, e := strconv.ParseUint(strings.TrimPrefix(s, "filter tree:"), 10, 31); e != nil {
				return out, fmt.Errorf("invalid filter")
			}
		default:
			return out, fmt.Errorf("unsupported fetch argument")
		}
	}
	if !args || out.Command == "" {
		return out, fmt.Errorf("incomplete v2 request")
	}
	return out, nil
}
