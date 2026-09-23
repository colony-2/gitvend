package jsonutil

import "testing"

func TestStrictJSON(t *testing.T) {
	type nested struct {
		A string `json:"a"`
	}
	type input struct {
		V nested `json:"v"`
	}
	for _, s := range []string{`{"v":{"a":"one","a":"two"}}`, `{"v":{},"extra":true}`, `{"v":{"x":1}}`, `{} {}`, `{"v":`} {
		var out input
		if e := Decode([]byte(s), &out); e == nil {
			t.Errorf("accepted %s", s)
		}
	}
	var out input
	if e := Decode([]byte(`{"v":{"a":"value"}}`), &out); e != nil || out.V.A != "value" {
		t.Fatal(e)
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"value":"ok"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var out struct {
			Value string `json:"value"`
		}
		Decode(b, &out)
	})
}
