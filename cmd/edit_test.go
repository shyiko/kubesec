package cmd

import (
	"os"
	"reflect"
	"regexp"
	"strings"
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

func TestEncryptDecryptDifferentKey(t *testing.T) {
	expected := "data:\n  key: value\nkind: Secret\n"
	encrypted, err := Encrypt([]byte(expected), EncryptionContext{
		Keys: Keys{Key{Fingerprint: "72ECF46A56B4AD39C907BBB71646B01B86E50310"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decrypt(encrypted); err == nil {
		t.Fail()
	} else {
		actual := err.Error()
		expected := "PGP key required to decrypt the \"data\" wasn't found"
		if actual != expected {
			t.Fatalf("actual: %#v != expected: %#v", actual, expected)
		}
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
	actual, err := Edit([]byte("data:\n  key: dmFsdWU=\nkind: Secret\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	expected := `data:
  key: ANYTHING
kind: Secret
# kubesec:v:1
# kubesec:pgp:ANYTHING`
	if !regexp.MustCompile(strings.Replace(regexp.QuoteMeta(expected), "ANYTHING", "[^\\n]*", -1)).
		MatchString(string(actual)) {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}

func TestEditEncrypted(t *testing.T) {
	os.Setenv("EDITOR", "true")
	encrypted, err := Encrypt([]byte("data:\n  key: dmFsdWU=\nkind: Secret\n"), EncryptionContext{})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := Edit(encrypted, false)
	if err != nil {
		t.Fatal(err)
	}
	expected := `data:
  key: ANYTHING
kind: Secret
# kubesec:v:1
# kubesec:pgp:ANYTHING`
	if !regexp.MustCompile(strings.Replace(regexp.QuoteMeta(expected), "ANYTHING", "[^\\n]*", -1)).
		MatchString(string(actual)) {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}
