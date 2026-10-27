package gitwire

import (
	"bytes"
	"io"
	"testing"
)

func TestPushShallowDeclarations(t *testing.T) {
	for _, newline := range []string{"", "\n"} {
		t.Run("newline="+newline, func(t *testing.T) {
			prefix := append(Line("shallow "+id1+newline), Line("shallow "+id2+newline)...)
			prefix = append(prefix, packets(zero+" "+id1+" refs/heads/new\x00report-status side-band-64k",
				id1+" "+id2+" refs/heads/main", "flush")...)
			body := append(append([]byte(nil), prefix...), []byte("PACKpayload")...)
			r := bytes.NewReader(body)
			push, err := ParsePush(r, len(prefix), 2)
			if err != nil {
				t.Fatal(err)
			}
			if push.Probe || len(push.Updates) != 2 || push.Updates[0].Action != "ref.create" || push.Updates[1].Action != "ref.update" || len(push.Capabilities) != 2 {
				t.Fatalf("incorrect shallow push: %+v", push)
			}
			pack, err := io.ReadAll(r)
			if err != nil || string(pack) != "PACKpayload" || !bytes.Equal(push.Prefix, prefix) {
				t.Fatal("shallow declarations changed or pack consumed")
			}
			for _, limits := range [][2]int{{len(prefix) - 1, 2}, {len(prefix), 1}} {
				if _, err := ParsePush(bytes.NewReader(body), limits[0], limits[1]); err == nil {
					t.Fatalf("shallow push bypassed limits: %v", limits)
				}
			}
		})
	}
}

func TestPushProbe(t *testing.T) {
	push, err := ParsePush(bytes.NewReader([]byte("0000")), 4, 1)
	if err != nil || !push.Probe || len(push.Updates) != 0 || len(push.Capabilities) != 0 || string(push.Prefix) != "0000" {
		t.Fatalf("probe: %+v, %v", push, err)
	}
	if _, err := ParsePush(bytes.NewReader([]byte("0000")), 3, 1); err == nil {
		t.Fatal("probe bypassed control byte limit")
	}
	if _, err := ParsePush(io.MultiReader(bytes.NewReader([]byte("0000")), pushReadError{}), 4, 1); err == nil {
		t.Fatal("probe accepted an incomplete HTTP body")
	}
}

type pushReadError struct{}

func (pushReadError) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRejectMalformedShallowPushesAndProbes(t *testing.T) {
	command := zero + " " + id1 + " refs/heads/main"
	for _, body := range [][]byte{
		nil, []byte("000"), []byte("0001"), []byte("0002"), []byte("0004"),
		[]byte("0000PACKpayload"), []byte("00000000"), packets("flush", command, "flush"),
		packets("shallow "+id1, "flush"), packets("shallow " + id1),
		packets("shallow bad", command, "flush"),
		packets("shallow "+id1+" "+id2, command, "flush"),
		packets("shallow "+id1+"\x00report-status", command, "flush"),
		packets("shallow "+id1+"\n"+command, "flush"),
		packets(command, "shallow "+id1, "flush"),
		packets("shallow "+id1, command, command, "flush"),
		packets("shallow "+id1, command+"\x00push-options", "flush"),
		packets("shallow "+id1, "push-cert\x00report-status", "flush"),
	} {
		if _, err := ParsePush(bytes.NewReader(body), 1<<20, 100); err == nil {
			t.Errorf("accepted malformed push: %q", body)
		}
	}
}
