package cmd

import (
	"testing"
)

func TestDecryptMalformed(t *testing.T) {
	for _, rs := range []string{
		`{}`,
		`{"kind": "ConfigMap"}`,
		`{"kind": "Secret", "data": ""}`,
		`{"kind": "Secret", "data": {key: 0}}`,
	} {
		if _, _, err := Decrypt([]byte(rs)); err == nil {
			t.Error(rs)
		}
	}
}

func TestDecryptGivenEmptyData(t *testing.T) {
	actual, _, err := Decrypt([]byte(`{"kind": "Secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	expected := "kind: Secret\n"
	if string(actual) != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}

func TestDecrypt(t *testing.T) {
	expected := "data:\n  KEY: dmFsdWUK\nkind: Secret\n"
	encrypted, err := EncryptWithContext([]byte(expected), EncryptionContext{})
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := Decrypt([]byte(encrypted))
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}
