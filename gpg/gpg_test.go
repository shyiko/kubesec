package gpg

import (
	"reflect"
	"testing"
)

func TestParseKeys(t *testing.T) {
	actual, err := parseKeys([]byte(`
pub:f:1024:17:6C7EE1B8621CC013:899817715:1055898235::m:::scESC:
fpr:::::::::ECAF7590EB3443B5C7CF3ACB6C7EE1B8621CC013:
uid:f::::::::Werner Koch <wk@g10code.com>:
uid:f::::::::Werner Koch <wk@gnupg.org>:
sub:f:1536:16:06AD222CADF6A6E1:919537416:1036177416:::::e:
fpr:::::::::CF8BCC4B18DE08FCD8A1615906AD222CADF6A6E1:
sub:r:1536:20:5CE086B5B5A18FF4:899817788:1025961788:::::esc:
fpr:::::::::AB059359A3B81F410FCFF97F5CE086B5B5A18FF4:
	`))
	if err != nil {
		t.Fatal(err)
	}
	expected := []Key{
		{
			Fingerprint:   "ECAF7590EB3443B5C7CF3ACB6C7EE1B8621CC013",
			KeyCapability: []KeyCapability{KCEncrypt, KCSign, KCCertify},
			Primary:       true,
			UserId:        "Werner Koch <wk@g10code.com>, Werner Koch <wk@gnupg.org>",
		},
		{
			Fingerprint:   "CF8BCC4B18DE08FCD8A1615906AD222CADF6A6E1",
			KeyCapability: []KeyCapability{KCEncrypt},
			Primary:       false,
		},
		{
			Fingerprint:   "AB059359A3B81F410FCFF97F5CE086B5B5A18FF4",
			KeyCapability: []KeyCapability{KCEncrypt, KCSign, KCCertify},
			Primary:       false,
		},
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("actual: %#v != expected: %#v", actual, expected)
	}
}

func TestParseSecretKeys(t *testing.T) {
	actual, err := parseKeys([]byte(`
sec:u:2048:1:14D4CA94236EC4A7:1502024599:::u:::scESC:::+::::
fpr:::::::::4943AC2D8BBC61B9113EE7EF14D4CA94236EC4A7:
uid:u::::1502024599::66BF978F7EF32F9247EC1FCC386EB56CE13DED10::Jean-Luc Picard (-) <jean-luc.picard@uss@enterprise-d>:::::::::
ssb:u:2048:1:E8C57A8030129DB0:1502024599::::::e:::+:::
	`))
	if err != nil {
		t.Fatal(err)
	}
	expected := []Key{
		{
			Fingerprint:   "4943AC2D8BBC61B9113EE7EF14D4CA94236EC4A7",
			KeyCapability: []KeyCapability{KCEncrypt, KCSign, KCCertify},
			Primary:       true,
			UserId:        "Jean-Luc Picard (-) <jean-luc.picard@uss@enterprise-d>",
		},
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("actual: %#v != expected: %#v", actual, expected)
	}
}
