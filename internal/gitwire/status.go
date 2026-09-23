package gitwire

import (
	"bytes"
	"fmt"
	"strings"
)

type PushStatus struct {
	Outcome string            `json:"outcome"`
	Unpack  string            `json:"unpack,omitempty"`
	Refs    map[string]string `json:"refs,omitempty"`
}

// Status is observational: it never replaces the upstream Git result sent to the client.
func Status(b []byte, updates []Update) PushStatus {
	unknown := PushStatus{Outcome: "unknown"}
	r := bytes.NewReader(b)
	var data bytes.Buffer
	side := false
	for r.Len() > 0 {
		p, e := Read(r)
		if e != nil {
			return unknown
		}
		if p.Kind != 3 {
			continue
		}
		if len(p.Data) > 0 && p.Data[0] >= 1 && p.Data[0] <= 3 {
			side = true
			if p.Data[0] == 1 {
				data.Write(p.Data[1:])
			}
			if p.Data[0] == 3 {
				return PushStatus{Outcome: "rejected", Unpack: "upstream fatal error"}
			}
		} else if side {
			return unknown
		}
	}
	if side {
		b = data.Bytes()
	}
	r = bytes.NewReader(b)
	out := PushStatus{Outcome: "unknown", Refs: map[string]string{}}
	valid := map[string]bool{}
	for _, u := range updates {
		valid[u.Ref] = true
	}
	for r.Len() > 0 {
		p, e := Read(r)
		if e != nil {
			return unknown
		}
		if p.Kind != 3 {
			continue
		}
		s := strings.TrimSuffix(string(p.Data), "\n")
		switch {
		case strings.HasPrefix(s, "unpack "):
			out.Unpack = strings.TrimPrefix(s, "unpack ")
		case strings.HasPrefix(s, "ok "):
			ref := strings.TrimPrefix(s, "ok ")
			if !valid[ref] {
				return unknown
			}
			out.Refs[ref] = "ok"
		case strings.HasPrefix(s, "ng "):
			ref, reason, _ := strings.Cut(strings.TrimPrefix(s, "ng "), " ")
			if !valid[ref] {
				return unknown
			}
			out.Refs[ref] = "rejected: " + reason
		case strings.HasPrefix(s, "option "):
			return unknown
		default:
			return unknown
		}
	}
	if out.Unpack != "" && out.Unpack != "ok" {
		out.Outcome = "rejected"
		return out
	}
	if out.Unpack == "ok" && len(out.Refs) == len(updates) {
		accepted := 0
		for _, s := range out.Refs {
			if s == "ok" {
				accepted++
			}
		}
		switch accepted {
		case len(out.Refs):
			out.Outcome = "accepted"
		case 0:
			out.Outcome = "rejected"
		default:
			out.Outcome = "partial"
		}
	}
	return out
}
func ExpectedContentType(service string, discovery bool) string {
	suffix := "result"
	if discovery {
		suffix = "advertisement"
	}
	return fmt.Sprintf("application/x-%s-%s", service, suffix)
}
