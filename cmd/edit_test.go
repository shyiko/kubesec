package cmd

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	expected := "data:\n  key: value\nkind: Secret\n"
	encrypted, err := Encrypt([]byte(expected), EncryptionContext{})
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}
