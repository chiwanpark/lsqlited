package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestValueRoundTrip(t *testing.T) {
	now := time.Date(2024, 5, 17, 12, 34, 56, 789000000, time.UTC)
	cases := []any{
		nil,
		int64(42),
		int64(-9223372036854775808),
		int64(9223372036854775807),
		3.14159,
		-0.0001,
		true,
		false,
		"hello, world",
		"",
		[]byte{0x00, 0x01, 0xff},
		[]byte{},
		now,
	}
	for _, want := range cases {
		enc, err := EncodeValue(want)
		if err != nil {
			t.Fatalf("EncodeValue(%#v): %v", want, err)
		}
		got, err := enc.Decode()
		if err != nil {
			t.Fatalf("Decode(%#v): %v", enc, err)
		}
		if wantTime, ok := want.(time.Time); ok {
			if !wantTime.Equal(got.(time.Time)) {
				t.Errorf("time round trip: got %v, want %v", got, wantTime)
			}
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("round trip: got %#v (%T), want %#v (%T)", got, got, want, want)
		}
	}
}

func TestEncodeValueUnsupported(t *testing.T) {
	if _, err := EncodeValue(struct{}{}); err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestDecodeValueUnknownTag(t *testing.T) {
	if _, err := (Value{T: "bogus"}).Decode(); err == nil {
		t.Fatal("expected error for unknown type tag")
	}
}

func TestMessageRoundTrip(t *testing.T) {
	req := Request{
		Type:     TypeQuery,
		Database: "app",
		Query:    "SELECT * FROM t WHERE id = ?",
		Args:     []Value{{T: TypeTagInt, V: "1"}},
	}
	var buf bytes.Buffer
	if err := WriteMessage(&buf, &req); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	var got Request
	if err := ReadMessage(&buf, &got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if !reflect.DeepEqual(got, req) {
		t.Errorf("round trip: got %#v, want %#v", got, req)
	}
}

// TestCompatibility pins the two directions of the additive fields: a peer
// that does not know them must not be able to tell, and a peer that does must
// cope with their absence.
func TestCompatibility(t *testing.T) {
	// A request without limits is on the wire exactly as it was before they
	// existed, so an older server sees nothing new.
	req := Request{Type: TypeQuery, Database: "app", Query: "SELECT 1"}
	encoded, err := json.Marshal(&req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	const want = `{"type":"query","database":"app","query":"SELECT 1"}`
	if string(encoded) != want {
		t.Errorf("request = %s, want %s", encoded, want)
	}

	// A response from a server that predates the new fields decodes with
	// them empty rather than failing.
	var resp Response
	old := `{"columns":["v"],"rows":[[{"t":"text","v":"hello"}]]}`
	if err := json.Unmarshal([]byte(old), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.ColumnTypes != nil {
		t.Errorf("column types = %v, want none", resp.ColumnTypes)
	}
	if resp.Code != "" {
		t.Errorf("code = %q, want none", resp.Code)
	}

	// A request from a client that predates them leaves the limits unset,
	// which is what "the client imposes no limit" looks like.
	var decoded Request
	if err := json.Unmarshal([]byte(want), &decoded); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	if decoded.TimeoutMS != 0 || decoded.MaxRows != 0 {
		t.Errorf("limits = %d/%d, want 0/0", decoded.TimeoutMS, decoded.MaxRows)
	}
	// A begin from such a client is a write transaction, which is the
	// safe reading of a request that does not say.
	if decoded.ReadOnly {
		t.Error("read_only = true, want false")
	}
}

func TestReadMessageTooLarge(t *testing.T) {
	var buf bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxMessageSize+1)
	buf.Write(header[:])
	var msg Request
	if err := ReadMessage(&buf, &msg); err == nil {
		t.Fatal("expected error for oversized message")
	}
}

func TestReadMessageTruncated(t *testing.T) {
	var buf bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 100)
	buf.Write(header[:])
	buf.WriteString("short")
	var msg Request
	if err := ReadMessage(&buf, &msg); err == nil {
		t.Fatal("expected error for truncated message")
	}
}
