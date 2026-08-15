package protocol

import (
	"bytes"
	"encoding/binary"
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
