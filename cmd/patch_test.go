package cmd

import (
	"testing"
)

func TestPatch(t *testing.T) {
	source := `data:
  another_key: value
  key: value
  key_to_remove: value
kind: Secret
metadata:
  name: original_name
`
	encrypted, err := EncryptCleartext([]byte(source), KeySetMutation{})
	if err != nil {
		t.Fatal(err)
	}
	assertPatchResultEq(t, encrypted, PatchOpt{}, source)
	assertPatchResultEq(t,
		encrypted,
		PatchOpt{Metadata: map[string]string{"name": "updated_name"}},
		`data:
  another_key: value
  key: value
  key_to_remove: value
kind: Secret
metadata:
  name: updated_name
`)
	assertPatchResultEq(t,
		encrypted,
		PatchOpt{Metadata: map[string]string{"namespace": "beyond"}},
		`data:
  another_key: value
  key: value
  key_to_remove: value
kind: Secret
metadata:
  name: original_name
  namespace: beyond
`)
	assertPatchResultEq(t,
		encrypted,
		PatchOpt{
			Metadata: map[string]string{"name": "updated-secret"},
			ClearTextDataMutation: map[string][]byte{
				"key":           []byte("updated_value"),
				"key_added":     []byte("value"),
				"key_to_remove": nil,
			},
		},
		`data:
  another_key: value
  key: updated_value
  key_added: value
kind: Secret
metadata:
  name: updated-secret
`)
}

func assertPatchResultEq(t *testing.T, enc []byte, opt PatchOpt, expected string) {
	result, err := Patch(enc, opt)
	if err != nil {
		t.Fatal(err)
	}
	actual, _, err := DecryptCleartext(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != expected {
		t.Fatalf("actual: %#v != expected: %#v", string(actual), expected)
	}
}
