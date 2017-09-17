package cmd

import (
	"github.com/shyiko/kubesec/gpg"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestEncryptMalformed(t *testing.T) {
	for _, rs := range []string{
		`{}`,
		`{"kind": "ConfigMap"}`,
		`{"kind": "Secret", "data": ""}`,
		`{"kind": "Secret", "data": {key: 0}}`,
	} {
		if _, err := EncryptWithContext([]byte(rs), EncryptionContext{}); err == nil {
			t.Error(rs)
		}
	}
}

func TestEncryptGivenEmptyData(t *testing.T) {
	actual, err := EncryptWithContext([]byte(`{"kind": "Secret"}`), EncryptionContext{})
	if err != nil {
		t.Fatal(err)
	}
	expected := "kind: Secret\n# kubesec:"
	if !strings.HasPrefix(string(actual), expected) {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}

func TestEncrypt(t *testing.T) {
	actual, err := EncryptWithContext([]byte(`{"kind": "Secret", "data": {"key": "value"}}`), EncryptionContext{})
	if err != nil {
		t.Fatal(err)
	}
	expected := "data:\n  key: ANYTHING\nkind: Secret\n# kubesec:"
	if !regexp.MustCompile(strings.Replace(regexp.QuoteMeta(expected), "ANYTHING", "[^\\n]*", 1)).
		MatchString(string(actual)) {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}

func TestKeyRotation(t *testing.T) {
	ctx := EncryptionContext{
		DEK: []byte{1},
		Keys: Keys{
			KeyWithDEK{Key{KTPGP, "2"}, []byte{3}},
			KeyWithDEK{Key{KTPGP, "4"}, []byte{5}},
		},
		Stash: map[string]interface{}{
			"key": "value",
		},
	}
	ctx.RotateDEK()
	if ctx.DEK != nil {
		t.Fatal("expected ctx.DEK != nil")
	}
	if len(ctx.Keys) != 2 {
		t.Fatal("expected len(ctx.Keys) != 1")
	}
	for _, key := range ctx.Keys {
		if key.EncryptedDEK != nil {
			t.Fatal("expected Keys[" + key.Id + "].EncryptedDEK != nil")
		}
	}
	if ctx.Stash != nil {
		t.Fatal("expected ctx.Stash != nil")
	}
}

func TestEncryptKeyAdd(t *testing.T) {
	input := "data:\n  key: value\nkind: Secret\n"
	encrypted, err := EncryptWithContext([]byte(input), EncryptionContext{})
	if err != nil {
		t.Fatal(err)
	}
	primaryKey, err := gpg.PrimaryKey()
	if err != nil {
		t.Fatal(err)
	}
	anotherFP := "72ECF46A56B4AD39C907BBB71646B01B86E50310"
	actual, err := Encrypt(encrypted, KeySetMutation{Add: []Key{{KTPGP, anotherFP}}})
	if err != nil {
		t.Fatal(err)
	}
	fps := []string{primaryKey.Fingerprint, anotherFP}
	sort.Strings(fps)
	expected := "data:\n  key: ANYTHING\nkind: Secret\n" + strings.Join([]string{
		"# kubesec:v:3",
		"# kubesec:pgp:" + fps[0] + ":ANYTHING",
		"# kubesec:pgp:" + fps[1] + ":ANYTHING",
		"# kubesec:mac:ANYTHING",
	}, "\n") + "\n"
	if !regexp.MustCompile(strings.Replace(regexp.QuoteMeta(expected), "ANYTHING", "[^\\n]*", -1)).
		MatchString(string(actual)) {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}

/*
func TestFingerprintRemoveLastOne(t *testing.T) {
	encrypted, err := EncryptWithContext([]byte("data:\n  key: value\nkind: Secret\n"), EncryptionContext{})
	if err != nil {
		t.Fatal(err)
	}
	primaryKey, err := gpg.PrimaryKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt(encrypted, KeySetMutation{Remove:[]string{primaryKey.ID}}); err == nil {
		t.Fail()
	}
}
*/

func TestEncryptKeyRemove(t *testing.T) {
	primaryKey, err := gpg.PrimaryKey()
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		primaryKey.Fingerprint,
		"72ECF46A56B4AD39C907BBB71646B01B86E50310",
	}
	encrypted, err := EncryptWithContext([]byte("data:\n  key: value\nkind: Secret\n"), EncryptionContext{
		Keys: Keys{
			KeyWithDEK{Key{KTPGP, expected[0]}, nil},
			KeyWithDEK{Key{KTPGP, expected[1]}, nil},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if encrypted, err := Encrypt(encrypted, KeySetMutation{
		Remove: []Key{{KTPGP, expected[1]}},
	}); err != nil {
		t.Fail()
	} else {
		ctx, err := reconstructEncryptionContext(encrypted, false, false)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := keyIds(ctx, KTPGP)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected[:1]) {
			t.Fatalf("actual: %#v != expected: %#v", actual, expected[:1])
		}
	}
}

func TestEncryptWithMissingKey(t *testing.T) {
	if _, err := EncryptWithContext([]byte(`{"kind": "Secret"}`), EncryptionContext{
		Keys: Keys{
			KeyWithDEK{Key{KTPGP, "B90F6449FEBC20F00DB13ED8212659B22565CA8"}, nil},
		},
	}); err == nil {
		t.Fail()
	} else {
		actual := err.Error()
		expected := "Failed to encrypt/sign DEK with PGP key B90F6449FEBC20F00DB13ED8212659B22565CA8 (re-run with --debug flag to get more details)"
		if actual != expected {
			t.Fatalf("actual: %#v != expected: %#v", actual, expected)
		}
	}
}
