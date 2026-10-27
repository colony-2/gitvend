package gitwire

import (
	"bytes"
	"testing"
)

func TestCapabilitiesWithUploadPackServiceHeader(t *testing.T) {
	advertisement := packets("version 2", "agent=git/github", "ls-refs=unborn",
		"fetch=shallow filter ref-in-want sideband-all packfile-uris wait-for-done",
		"server-option", "bundle-uri", "object-format=sha1", "flush")
	want := packets("version 2", "agent=git/github", "ls-refs=unborn",
		"fetch=shallow filter wait-for-done", "object-format=sha1", "flush")
	for _, tt := range []struct {
		name   string
		prefix []byte
	}{
		{"bare v2", nil},
		{"GitHub service header", packets("# service=git-upload-pack", "flush")},
		{"service header without optional LF", append(Line("# service=git-upload-pack"), []byte("0000")...)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out, err := FilterCapabilities(append(tt.prefix, advertisement...))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, want) {
				t.Fatalf("filtered advertisement = %q, want %q", out, want)
			}
		})
	}
}

func TestCapabilitiesRejectInvalidServiceHeadersAndDowngrades(t *testing.T) {
	valid := packets("# service=git-upload-pack", "flush", "version 2", "ls-refs", "fetch", "flush")
	for _, tt := range []struct {
		name string
		body []byte
	}{
		{"wrong service", packets("# service=git-receive-pack", "flush", "version 2", "flush")},
		{"service suffix", packets("# service=git-upload-pack extra", "flush", "version 2", "flush")},
		{"missing service flush", packets("# service=git-upload-pack", "version 2", "flush")},
		{"delimiter instead of flush", packets("# service=git-upload-pack", "delim", "version 2", "flush")},
		{"response end instead of flush", append(Line("# service=git-upload-pack\n"), []byte("0002")...)},
		{"truncated header", []byte("001e# service=git-upload")},
		{"header only", packets("# service=git-upload-pack")},
		{"missing version", packets("# service=git-upload-pack", "flush")},
		{"extra flush", packets("# service=git-upload-pack", "flush", "flush", "version 2", "flush")},
		{"repeated header", packets("# service=git-upload-pack", "flush", "# service=git-upload-pack", "flush", "version 2", "flush")},
		{"bare v0", packets(id1+" refs/heads/main\x00multi_ack", "flush")},
		{"bare v1", packets("version 1", id1+" refs/heads/main\x00multi_ack", "flush")},
		{"wrapped v0", packets("# service=git-upload-pack", "flush", id1+" refs/heads/main\x00multi_ack", "flush")},
		{"wrapped v1", packets("# service=git-upload-pack", "flush", "version 1", id1+" refs/heads/main\x00multi_ack", "flush")},
		{"unsupported object format", packets("# service=git-upload-pack", "flush", "version 2", "object-format=sha256", "flush")},
		{"missing final flush", valid[:len(valid)-4]},
		{"trailing data", append(append([]byte(nil), valid...), []byte("extra")...)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if out, err := FilterCapabilities(tt.body); err == nil || out != nil {
				t.Fatalf("accepted invalid advertisement: %q, %v", out, err)
			}
		})
	}
}
