package protocol

import (
	"database/sql/driver"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"
)

// Value type tags. All values are transported as strings to preserve full precision (e.g. int64 values beyond 2^53
// would lose precision as JSON numbers).
const (
	TypeTagNull  = "null"
	TypeTagInt   = "int"
	TypeTagFloat = "float"
	TypeTagBool  = "bool"
	TypeTagText  = "text"
	TypeTagBlob  = "blob" // base64 (standard encoding)
	TypeTagTime  = "time" // RFC 3339 with nanoseconds
)

// Value is a typed SQL value that survives a JSON round trip.
type Value struct {
	T string `json:"t"`
	V string `json:"v,omitempty"`
}

// EncodeValue converts a Go value produced by database/sql or database/sql/driver into a wire Value.
func EncodeValue(v any) (Value, error) {
	switch v := v.(type) {
	case nil:
		return Value{T: TypeTagNull}, nil
	case int64:
		return Value{T: TypeTagInt, V: strconv.FormatInt(v, 10)}, nil
	case float64:
		return Value{T: TypeTagFloat, V: strconv.FormatFloat(v, 'g', -1, 64)}, nil
	case bool:
		return Value{T: TypeTagBool, V: strconv.FormatBool(v)}, nil
	case []byte:
		return Value{T: TypeTagBlob, V: base64.StdEncoding.EncodeToString(v)}, nil
	case string:
		return Value{T: TypeTagText, V: v}, nil
	case time.Time:
		return Value{T: TypeTagTime, V: v.Format(time.RFC3339Nano)}, nil
	default:
		return Value{}, fmt.Errorf("protocol: unsupported value type %T", v)
	}
}

// Decode converts a wire Value back into a driver.Value.
func (v Value) Decode() (driver.Value, error) {
	switch v.T {
	case TypeTagNull:
		return nil, nil
	case TypeTagInt:
		n, err := strconv.ParseInt(v.V, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("protocol: invalid int value %q: %w", v.V, err)
		}
		return n, nil
	case TypeTagFloat:
		f, err := strconv.ParseFloat(v.V, 64)
		if err != nil {
			return nil, fmt.Errorf("protocol: invalid float value %q: %w", v.V, err)
		}
		return f, nil
	case TypeTagBool:
		b, err := strconv.ParseBool(v.V)
		if err != nil {
			return nil, fmt.Errorf("protocol: invalid bool value %q: %w", v.V, err)
		}
		return b, nil
	case TypeTagBlob:
		b, err := base64.StdEncoding.DecodeString(v.V)
		if err != nil {
			return nil, fmt.Errorf("protocol: invalid blob value: %w", err)
		}
		return b, nil
	case TypeTagText:
		return v.V, nil
	case TypeTagTime:
		t, err := time.Parse(time.RFC3339Nano, v.V)
		if err != nil {
			return nil, fmt.Errorf("protocol: invalid time value %q: %w", v.V, err)
		}
		return t, nil
	default:
		return nil, fmt.Errorf("protocol: unknown value type tag %q", v.T)
	}
}

// EncodeValues encodes a slice of Go values.
func EncodeValues(vals []any) ([]Value, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	out := make([]Value, len(vals))
	for i, v := range vals {
		enc, err := EncodeValue(v)
		if err != nil {
			return nil, err
		}
		out[i] = enc
	}
	return out, nil
}

// DecodeValues decodes a slice of wire Values into []any suitable for passing to database/sql query methods.
func DecodeValues(vals []Value) ([]any, error) {
	if len(vals) == 0 {
		return nil, nil
	}
	out := make([]any, len(vals))
	for i, v := range vals {
		dec, err := v.Decode()
		if err != nil {
			return nil, err
		}
		out[i] = dec
	}
	return out, nil
}
