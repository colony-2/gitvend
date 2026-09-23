package gitwire

import (
	"bytes"
	"fmt"
	"strings"
)

// FilterCapabilities rejects downgrade responses and advertises only features this gate understands.
func FilterCapabilities(b []byte) ([]byte, error) {
	r := bytes.NewReader(b)
	p, e := Read(r)
	if e != nil || p.Kind != 3 || string(p.Data) != "version 2\n" {
		return nil, fmt.Errorf("upstream must speak Git protocol v2")
	}
	var out bytes.Buffer
	Write(&out, p)
	for {
		p, e = Read(r)
		if e != nil {
			return nil, e
		}
		if p.Kind == 0 {
			if r.Len() != 0 {
				return nil, fmt.Errorf("trailing advertisement")
			}
			out.WriteString("0000")
			break
		}
		if p.Kind != 3 {
			return nil, fmt.Errorf("invalid capability framing")
		}
		s := strings.TrimSuffix(string(p.Data), "\n")
		switch {
		case s == "object-format=sha1", strings.HasPrefix(s, "agent="):
			Write(&out, p)
		case strings.HasPrefix(s, "object-format="):
			return nil, fmt.Errorf("only SHA-1 repositories are supported")
		case s == "ls-refs" || strings.HasPrefix(s, "ls-refs="):
			v := "ls-refs"
			if strings.Contains(s, "unborn") {
				v += "=unborn"
			}
			out.Write(Line(v + "\n"))
		case s == "fetch" || strings.HasPrefix(s, "fetch="):
			features := []string{}
			_, f, _ := strings.Cut(s, "=")
			for _, a := range strings.Fields(f) {
				switch a {
				case "shallow", "filter", "wait-for-done":
					features = append(features, a)
				}
			}
			v := "fetch"
			if len(features) > 0 {
				v += "=" + strings.Join(features, " ")
			}
			out.Write(Line(v + "\n"))
		}
	}
	return out.Bytes(), nil
}
func FilterRefs(b []byte, prefixes []string, visible func(string) bool) ([]byte, error) {
	r := bytes.NewReader(b)
	var out bytes.Buffer
	for {
		p, e := Read(r)
		if e != nil {
			return nil, e
		}
		if p.Kind == 0 {
			out.WriteString("0000")
			if r.Len() > 0 {
				end, e := Read(r)
				if e != nil || end.Kind != 2 || r.Len() != 0 {
					return nil, fmt.Errorf("trailing refs")
				}
				out.WriteString("0002")
			}
			break
		}
		if p.Kind != 3 {
			return nil, fmt.Errorf("invalid refs framing")
		}
		f := strings.Fields(string(p.Data))
		if len(f) < 2 || !(OID(f[0]) || f[0] == "unborn") {
			return nil, fmt.Errorf("invalid ref record")
		}
		ref := f[1]
		target := ""
		for _, a := range f[2:] {
			switch {
			case strings.HasPrefix(a, "symref-target:"):
				target = strings.TrimPrefix(a, "symref-target:")
			case strings.HasPrefix(a, "peeled:"):
				if !OID(strings.TrimPrefix(a, "peeled:")) {
					return nil, fmt.Errorf("invalid peeled ID")
				}
			default:
				return nil, fmt.Errorf("unknown ref attribute")
			}
		}
		keep := visible(ref)
		if ref == "HEAD" {
			keep = target != "" && visible(target)
		} else if target != "" {
			keep = keep && visible(target)
		}
		if f[0] == "unborn" && target == "" {
			keep = false
		}
		if len(prefixes) > 0 {
			matched := false
			for _, pre := range prefixes {
				if strings.HasPrefix(ref, pre) {
					matched = true
				}
			}
			keep = keep && matched
		}
		if keep {
			Write(&out, p)
		}
	}
	return out.Bytes(), nil
}
func FilterPushAdvertisement(b []byte, visible func(string) bool) ([]byte, error) {
	r := bytes.NewReader(b)
	p, e := Read(r)
	if e != nil || p.Kind != 3 || string(p.Data) != "# service=git-receive-pack\n" {
		return nil, fmt.Errorf("invalid receive-pack advertisement")
	}
	p, e = Read(r)
	if e != nil || p.Kind != 0 {
		return nil, fmt.Errorf("invalid service header")
	}
	records := []string{}
	caps := []string{}
	first := true
	for {
		p, e = Read(r)
		if e != nil {
			return nil, e
		}
		if p.Kind == 0 {
			break
		}
		if p.Kind != 3 {
			return nil, fmt.Errorf("invalid advertisement framing")
		}
		line := strings.TrimSuffix(string(p.Data), "\n")
		left, right, has := strings.Cut(line, "\x00")
		if has {
			if !first {
				return nil, fmt.Errorf("misplaced capabilities")
			}
			for _, c := range strings.Fields(right) {
				if strings.HasPrefix(c, "object-format=") && c != "object-format=sha1" {
					return nil, fmt.Errorf("only SHA-1 supported")
				}
				if strings.HasPrefix(c, "symref=") {
					_, target, _ := strings.Cut(strings.TrimPrefix(c, "symref="), ":")
					if visible(target) {
						caps = append(caps, c)
					}
					continue
				}
				if pushCap(c) {
					caps = append(caps, c)
				}
			}
		}
		first = false
		f := strings.Fields(left)
		if len(f) != 2 || !OID(f[0]) {
			return nil, fmt.Errorf("invalid advertised ref")
		}
		if visible(f[1]) {
			records = append(records, left)
		}
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("trailing advertisement data")
	}
	var out bytes.Buffer
	out.Write(Line("# service=git-receive-pack\n"))
	out.WriteString("0000")
	if len(records) == 0 {
		records = []string{strings.Repeat("0", 40) + " capabilities^{}"}
	}
	for i, line := range records {
		if i == 0 {
			line += "\x00" + strings.Join(caps, " ")
		}
		out.Write(Line(line + "\n"))
	}
	out.WriteString("0000")
	return out.Bytes(), nil
}
