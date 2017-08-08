package aes

import (
	"strings"
	"testing"
)

func TestEncrypt(t *testing.T) {
	expected := "ZHNaYVQ=.ZmZmZmZmZmZmZmZm.pcgqz0hb478fIRa/buj8CA=="
	dek := []byte(strings.Repeat("f", 32))
	actual, err := Cipher{}.Encrypt("VALUE", dek, "KEY",
		stashedValue{iv: []byte(strings.Repeat("f", 12)), plaintext: "VALUE"})
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}

func TestEncryptEmpty(t *testing.T) {
	expected := ""
	dek := []byte(strings.Repeat("f", 32))
	actual, err := Cipher{}.Encrypt("", dek, "KEY",
		stashedValue{iv: []byte(strings.Repeat("f", 12)), plaintext: "VALUE"})
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}

func TestDecrypt(t *testing.T) {
	expected := "VALUE"
	dek := []byte(strings.Repeat("f", 32))
	cipher := Cipher{}
	encryptedValue, err := cipher.Encrypt(expected, dek, "KEY", nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := cipher.Decrypt(encryptedValue, dek, "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
	for _, node := range []struct {
		value string
		key   []byte
		path  string
	}{
		{encryptedValue, dek, "DIFFERENT_KEY"},
		{encryptedValue, []byte(strings.Repeat("g", 32)), "KEY"},
		{strings.Replace(encryptedValue, ".", "_", 1), dek, "KEY"},
	} {
		if _, _, err := cipher.Decrypt(node.value, node.key, node.path); err == nil {
			t.Fatal()
		}
	}
}

func TestDecryptEmpty(t *testing.T) {
	expected := ""
	dek := []byte(strings.Repeat("f", 32))
	encryptedValue, err := Cipher{}.Encrypt(expected, dek, "KEY", nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := Cipher{}.Decrypt(encryptedValue, dek, "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}
