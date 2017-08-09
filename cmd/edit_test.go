package cmd

import (
	"reflect"
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

func TestParseCommand(t *testing.T) {
	actual := parseCommand(`path/to/bin arg1 "arg2" 'arg3' "'" '"' "" '' "a g" 'a g' "\"" '\''`)
	expected := []string{"path/to/bin", "arg1", "arg2", "arg3", "'", "\"", "", "", "a g", "a g", "\"", "'"}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("actual: %#v != expected: %#v", actual, expected)
	}
}
