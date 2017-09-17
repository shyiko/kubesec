package cmd

import (
	"github.com/shyiko/kubesec/gpg"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	expected := "data:\n  key: dmFsdWU=\nkind: Secret\n"
	encrypted, err := EncryptWithContext([]byte(expected), EncryptionContext{})
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

func TestEncryptDecryptDifferentKey(t *testing.T) {
	expected := "data:\n  key: dmFsdWU=\nkind: Secret\n"
	encrypted, err := EncryptWithContext([]byte(expected), EncryptionContext{
		Keys: Keys{
			KeyWithDEK{Key{KTPGP, "72ECF46A56B4AD39C907BBB71646B01B86E50310"}, nil},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decrypt(encrypted); err == nil {
		t.Fail()
	} else {
		actual := err.Error()
		expected := "Unable to decrypt Data Encryption Key (DEK)"
		if actual != expected {
			t.Fatalf("actual: %#v != expected: %#v", actual, expected)
		}
	}
}

func TestKeyChange(t *testing.T) {
	awsKMSKey := os.Getenv("KUBESEC_TEST_AWS_KMS_KEY")
	if awsKMSKey == "" {
		t.Skipf("KUBESEC_TEST_AWS_KMS_KEY is not defined")
	}
	gcpKMSKey := os.Getenv("KUBESEC_TEST_GCP_KMS_KEY")
	if gcpKMSKey == "" {
		t.Skipf("KUBESEC_TEST_GCP_KMS_KEY is not defined")
	}
	expected := "data:\n  key: dmFsdWU=\nkind: Secret\n"
	pgpKey, err := gpg.PrimaryKey()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptWithContext([]byte(expected), EncryptionContext{
		Keys: Keys{
			KeyWithDEK{Key{KTPGP, pgpKey.Fingerprint}, nil},
			KeyWithDEK{Key{KTAWSKMS, awsKMSKey}, nil},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	actualEncrypted, err := Edit(encrypted, EditOpt{
		KeySetMutation: KeySetMutation{
			Remove: []Key{{KTAWSKMS, awsKMSKey}},
			Add:    []Key{{KTGCPKMS, gcpKMSKey}},
		},
		Editor: "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := Decrypt(actualEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
	ctx, err := reconstructEncryptionContext(actualEncrypted, false, false)
	if err != nil {
		t.Fatal(err)
	}
	var actualKeys []Key
	for _, key := range ctx.Keys {
		actualKeys = append(actualKeys, key.Key)
	}
	expectedKeys := []Key{
		{KTPGP, pgpKey.Fingerprint},
		{KTGCPKMS, gcpKMSKey},
	}
	if !reflect.DeepEqual(actualKeys, expectedKeys) {
		t.Fatalf("actual: %#v != expected: %#v", actualKeys, expectedKeys)
	}
}

func TestParseCommand(t *testing.T) {
	actual := parseCommand(`path/to/bin arg1 "arg2" 'arg3' "'" '"' "" '' "a g" 'a g' "\"" '\''`)
	expected := []string{"path/to/bin", "arg1", "arg2", "arg3", "'", "\"", "", "", "a g", "a g", "\"", "'"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("actual: %#v != expected: %#v", actual, expected)
	}
}

func TestEditUnencrypted(t *testing.T) {
	os.Setenv("EDITOR", "true")
	actual, err := Edit([]byte("data:\n  key: dmFsdWU=\nkind: Secret\n"), EditOpt{})
	if err != nil {
		t.Fatal(err)
	}
	expected := `data:
  key: ANYTHING
kind: Secret
# kubesec:v:3
# kubesec:pgp:ANYTHING
# kubesec:mac:ANYTHING`
	if !regexp.MustCompile(strings.Replace(regexp.QuoteMeta(expected), "ANYTHING", "[^\\n]*", -1)).
		MatchString(string(actual)) {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}

func TestEditEncrypted(t *testing.T) {
	os.Setenv("EDITOR", "true")
	encrypted, err := EncryptWithContext([]byte("data:\n  key: dmFsdWU=\nkind: Secret\n"), EncryptionContext{})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := Edit(encrypted, EditOpt{})
	if err != nil {
		t.Fatal(err)
	}
	expected := `data:
  key: ANYTHING
kind: Secret
# kubesec:v:3
# kubesec:pgp:ANYTHING
# kubesec:mac:ANYTHING`
	if !regexp.MustCompile(strings.Replace(regexp.QuoteMeta(expected), "ANYTHING", "[^\\n]*", -1)).
		MatchString(string(actual)) {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}
