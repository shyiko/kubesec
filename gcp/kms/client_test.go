package kms

import (
	"os"
	"testing"
)

func TestEncrypt(t *testing.T) {
	key := os.Getenv("KUBESEC_TEST_GCP_KMS_KEY")
	if key == "" {
		t.Skipf("KUBESEC_TEST_GCP_KMS_KEY is not defined")
	}
	client, err := New()
	if err != nil {
		t.Fatal(err)
	}
	expected := "priority message to Jean-Luc Picard"
	encryptedValue, err := client.Encrypt(key, []byte(expected))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := client.Decrypt(key, encryptedValue)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}
