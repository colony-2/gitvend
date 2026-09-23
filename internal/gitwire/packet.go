// Package gitwire handles the small control portions of Git smart HTTP. Packs are streamed.
package gitwire

import (
	"encoding/hex"
	"fmt"
	"io"
)

const MaxPacket = 65520

type Packet struct {
	Kind int
	Data []byte
}

func Read(r io.Reader) (Packet, error) {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return Packet{}, e
	}
	var n [2]byte
	if _, e := hex.Decode(n[:], h[:]); e != nil {
		return Packet{}, fmt.Errorf("invalid pkt-line length")
	}
	size := int(n[0])*256 + int(n[1])
	if size <= 2 {
		return Packet{Kind: size}, nil
	}
	if size < 4 || size > MaxPacket {
		return Packet{}, fmt.Errorf("invalid pkt-line size")
	}
	b := make([]byte, size-4)
	_, e := io.ReadFull(r, b)
	return Packet{Kind: 3, Data: b}, e
}
func Encode(p Packet) []byte {
	if p.Kind < 3 {
		return []byte(fmt.Sprintf("%04x", p.Kind))
	}
	return append([]byte(fmt.Sprintf("%04x", len(p.Data)+4)), p.Data...)
}
func Line(s string) []byte              { return Encode(Packet{Kind: 3, Data: []byte(s)}) }
func Write(w io.Writer, p Packet) error { _, e := w.Write(Encode(p)); return e }
