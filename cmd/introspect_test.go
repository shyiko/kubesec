package cmd

import (
	"reflect"
	"testing"
)

func TestIntrospectUnencrypted(t *testing.T) {
	if _, err := Introspect([]byte("data:\n  key: value\nkind: Secret\n")); err == nil {
		t.Fail()
	} else {
		actual := err.Error()
		expected := "Not encrypted"
		if actual != expected {
			t.Fatalf("actual: %#v != expected: %#v", actual, expected)
		}
	}
}

func TestIntrospect(t *testing.T) {
	expected := []string{
		"160A7A9CF46221A56B06AD64461A804F2609FD89",
		"72ECF46A56B4AD39C907BBB71646B01B86E50310",
	}
	encrypted, err := Encrypt([]byte("data:\n  key: value\nkind: Secret\n"), EncryptionContext{
		Keys: Keys{
			Key{Fingerprint: expected[0]},
			Key{Fingerprint: expected[1]},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := listPGPFP(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("actual: %#v != expected: %#v", actual, expected)
	}
}
