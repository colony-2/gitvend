package gitwire

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

var id1 = strings.Repeat("1", 40)
var id2 = strings.Repeat("2", 40)
var zero = strings.Repeat("0", 40)

func packets(lines ...string) []byte {
	var b bytes.Buffer
	for _, s := range lines {
		switch s {
		case "flush":
			b.WriteString("0000")
		case "delim":
			b.WriteString("0001")
		default:
			b.Write(Line(s + "\n"))
		}
	}
	return b.Bytes()
}
func TestPacket(t *testing.T) {
	for _, b := range [][]byte{[]byte("zzzz"), []byte("0003"), []byte("ffff"), []byte("0008ab")} {
		if _, e := Read(bytes.NewReader(b)); e == nil {
			t.Errorf("accepted %q", b)
		}
	}
	for _, p := range []Packet{{Kind: 0}, {Kind: 1}, {Kind: 2}, {Kind: 3, Data: []byte("hello")}} {
		q, e := Read(bytes.NewReader(Encode(p)))
		if e != nil || p.Kind != q.Kind || !bytes.Equal(p.Data, q.Data) {
			t.Fatalf("roundtrip %+v %+v %v", p, q, e)
		}
	}
}
func TestPush(t *testing.T) {
	b := packets(zero+" "+id1+" refs/heads/agent\x00report-status side-band-64k", id1+" "+id2+" refs/heads/next", id1+" "+zero+" refs/tags/old", "flush")
	b = append(b, []byte("PACKpayload")...)
	r := bytes.NewReader(b)
	p, e := ParsePush(r, 1<<20, 100)
	if e != nil {
		t.Fatal(e)
	}
	want := []string{"ref.create", "ref.update", "ref.delete"}
	for i, u := range p.Updates {
		if u.Action != want[i] {
			t.Fatal(u)
		}
	}
	pack, _ := io.ReadAll(r)
	if string(pack) != "PACKpayload" || !bytes.Equal(append(p.Prefix, pack...), b) {
		t.Fatal("pack consumed or prefix modified")
	}
}
func TestPushRejected(t *testing.T) {
	valid := zero + " " + id1 + " refs/heads/main"
	for _, b := range [][]byte{packets("flush"), packets(valid+"\x00push-options", "flush"), packets(valid, valid, "flush"), packets(zero+" "+zero+" refs/heads/main", "flush"), packets(zero+" "+id1+" refs/heads/a..b", "flush"), packets(valid+"\x00object-format=sha256", "flush"), packets(valid, "delim"), packets("shallow "+id1, valid, "flush"), packets("push-cert\x00report-status", "flush")} {
		if _, e := ParsePush(bytes.NewReader(b), 1<<20, 100); e == nil {
			t.Errorf("accepted %q", b)
		}
	}
	if _, e := ParsePush(bytes.NewReader(packets(valid, "flush")), 5, 100); e == nil {
		t.Fatal("byte limit")
	}
	if _, e := ParsePush(bytes.NewReader(packets(valid, "flush")), 1024, 0); e == nil {
		t.Fatal("ref limit")
	}
}
func TestFetch(t *testing.T) {
	for _, cmd := range []string{"ls-refs", "fetch"} {
		args := []string{"command=" + cmd, "agent=git/2", "delim"}
		if cmd == "fetch" {
			args = append(args, "want "+id1, "filter blob:none", "deepen 1", "done")
		} else {
			args = append(args, "symrefs", "peel", "ref-prefix refs/heads/")
		}
		args = append(args, "flush")
		f, e := ParseFetch(packets(args...))
		if e != nil || f.Command != cmd {
			t.Fatal(f, e)
		}
	}
	for _, arg := range []string{"want-ref refs/heads/hidden", "deepen-not hidden", "filter sparse:oid=hidden", "packfile-uris https", "want deadbeef", "server-option=unsafe", "deepen -1"} {
		if _, e := ParseFetch(packets("command=fetch", "delim", arg, "flush")); e == nil {
			t.Errorf("accepted %s", arg)
		}
	}
	for _, b := range [][]byte{packets("command=object-info", "delim", "flush"), packets("command=ls-refs", "command=fetch", "delim", "flush"), append(packets("command=fetch", "delim", "flush"), []byte("extra")...), packets("command=fetch", "flush")} {
		if _, e := ParseFetch(b); e == nil {
			t.Errorf("accepted %q", b)
		}
	}
}
func TestCapabilities(t *testing.T) {
	b := packets("version 2", "agent=git/2", "ls-refs=unborn", "fetch=shallow filter ref-in-want sideband-all packfile-uris wait-for-done", "server-option", "bundle-uri", "object-format=sha1", "flush")
	out, e := FilterCapabilities(b)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"ref-in-want", "sideband-all", "server-option", "bundle-uri", "packfile-uris"} {
		if bytes.Contains(out, []byte(s)) {
			t.Fatal(s)
		}
	}
	if !bytes.Contains(out, []byte("fetch=shallow filter wait-for-done")) {
		t.Fatal(string(out))
	}
	if _, e := FilterCapabilities(packets(id1+" refs/heads/main", "flush")); e == nil {
		t.Fatal("downgrade")
	}
	if _, e := FilterCapabilities(packets("version 2", "object-format=sha256", "flush")); e == nil {
		t.Fatal("format")
	}
}
func TestFilterRefs(t *testing.T) {
	visible := func(r string) bool { return r == "refs/heads/agent" }
	b := packets(id1+" HEAD symref-target:refs/heads/secret", id1+" refs/heads/secret", id2+" refs/heads/agent", id1+" refs/tags/secret peeled:"+id2, "unborn refs/heads/alias symref-target:refs/heads/secret", "flush")
	out, e := FilterRefs(b, nil, visible)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out, packets(id2+" refs/heads/agent", "flush")) {
		t.Fatal(string(out))
	}
	out, e = FilterRefs(b, []string{"refs/tags/"}, visible)
	if e != nil || string(out) != "0000" {
		t.Fatal(string(out), e)
	}
	head := packets("unborn HEAD symref-target:refs/heads/agent", "flush")
	out, e = FilterRefs(head, nil, visible)
	if e != nil || !bytes.Equal(out, head) {
		t.Fatal(string(out), e)
	}
}
func TestPushAdvertisement(t *testing.T) {
	b := packets("# service=git-receive-pack", "flush", id1+" refs/heads/secret\x00report-status push-options push-cert=nonce atomic symref=HEAD:refs/heads/secret object-format=sha1", id2+" refs/heads/agent", id1+" .have", "flush")
	out, e := FilterPushAdvertisement(b, func(r string) bool { return r == "refs/heads/agent" })
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"secret", ".have", "push-options", "push-cert", "symref="} {
		if bytes.Contains(out, []byte(s)) {
			t.Fatal(s)
		}
	}
	if !bytes.Contains(out, []byte("refs/heads/agent\x00report-status atomic object-format=sha1")) {
		t.Fatal(string(out))
	}
	out, e = FilterPushAdvertisement(b, func(string) bool { return false })
	if e != nil || !bytes.Contains(out, []byte(zero+" capabilities^{}\x00report-status")) {
		t.Fatal(string(out), e)
	}
}
func FuzzWire(f *testing.F) {
	f.Add(packets("command=ls-refs", "delim", "flush"))
	f.Add(packets(zero+" "+id1+" refs/heads/main", "flush"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		ParsePush(bytes.NewReader(b), 65536, 100)
		ParseFetch(b)
		FilterCapabilities(b)
		FilterRefs(b, nil, func(string) bool { return false })
		FilterPushAdvertisement(b, func(string) bool { return false })
	})
}

func TestStatus(t *testing.T) {
	updates := []Update{{Ref: "refs/heads/a"}, {Ref: "refs/heads/b"}}
	for _, tt := range []struct {
		body []byte
		want string
	}{{packets("unpack ok", "ok refs/heads/a", "ok refs/heads/b", "flush"), "accepted"}, {packets("unpack ok", "ok refs/heads/a", "ng refs/heads/b hook declined", "flush"), "partial"}, {packets("unpack bad pack", "flush"), "rejected"}, {packets("unpack ok", "ng refs/heads/a no", "ng refs/heads/b no", "flush"), "rejected"}, {packets("unpack ok", "ok refs/heads/a", "flush"), "unknown"}, {packets("unpack ok", "ok refs/heads/other", "flush"), "unknown"}, {[]byte("bad"), "unknown"}, {packets("unpack ok", "option refname refs/heads/other", "flush"), "unknown"}} {
		if got := Status(tt.body, updates).Outcome; got != tt.want {
			t.Errorf("%q got %s want %s", tt.body, got, tt.want)
		}
	}
	inner := packets("unpack ok", "ok refs/heads/a", "ok refs/heads/b", "flush")
	outer := append(Line("\x02progress\n"), Line("\x01"+string(inner))...)
	outer = append(outer, []byte("0000")...)
	if got := Status(outer, updates).Outcome; got != "accepted" {
		t.Fatal(got)
	}
	if got := Status(Line("\x03failure"), updates).Outcome; got != "rejected" {
		t.Fatal(got)
	}
}
