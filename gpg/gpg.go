package gpg

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

/*
func init() {
	log.SetLevel(log.DebugLevel)
}
*/

type KeyCapability int
type KeyCapabilities []KeyCapability

// sort.Interface

func (f KeyCapabilities) Len() int {
	return len(f)
}

func (f KeyCapabilities) Less(i int, j int) bool {
	return f[i] < f[j]
}

func (f KeyCapabilities) Swap(i int, j int) {
	f[i], f[j] = f[j], f[i]
}

const (
	KCEncrypt KeyCapability = iota
	KCSign
	KCCertify
	KCAuthentication
)

type Key struct {
	Fingerprint   string
	KeyCapability KeyCapabilities
	Primary       bool
	UserId        []string
}

var pathToGPG string
var keyring string // fixme: global state is bad but it's 2am, sorry

func gpg() string {
	if pathToGPG == "" {
		cmd := exec.Command("which", "gpg2", "/usr/bin/gpg2", "gpg", "/usr/bin/gpg")
		out, _ := cmd.Output()
		if len(out) == 0 {
			log.Fatal("`gpg` wasn't found (make sure it's available on the PATH)")
		}
		pathToGPG = strings.Split(string(out), "\n")[0]
	}
	return pathToGPG
}

func SetKeyring(path string) {
	keyring = path
}

// http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS
func PrimaryKey() (Key, error) {
	keys, err := ListSecretKeys()
	if err != nil {
		return Key{}, err
	}
	for _, key := range keys {
		if key.Primary {
			return key, nil
		}
	}
	return Key{}, errors.New("Primary PGP key wasn't found")
}

func parseKeys(data []byte) ([]Key, error) {
	var keys []*Key
	var key *Key
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 10 {
			// - pub :: Public key
			// ...
			// - sub :: Subkey (secondary key)
			// ...
			// - sec :: Secret key
			// - ssb :: Secret subkey (secondary key)
			// - uid :: User id
			// ...
			// - fpr :: Fingerprint
			// ...
			typeOfRecord := fields[0]
			if typeOfRecord == "sec" || typeOfRecord == "ssb" || typeOfRecord == "pub" || typeOfRecord == "sub" {
				// The defined capabilities are:
				//
				//	- e :: Encrypt
				//	- s :: Sign
				//	- c :: Certify
				//	- a :: Authentication
				//	- ? :: Unknown capability
				//
				//	A key may have any combination of them in any order. In addition
				//	to these letters, the primary key has uppercase versions of the
				//	letters to denote the _usable_ capabilities of the entire key, and
				//	a potential letter 'D' to indicate a disabled key.
				keyCapabilitiesString := fields[11]
				if !strings.Contains(keyCapabilitiesString, "D") {
					key = &Key{}
					keyCapabilitiesMap := make(map[KeyCapability]bool)
					for _, c := range strings.ToLower(keyCapabilitiesString) {
						switch c {
						case 'e':
							keyCapabilitiesMap[KCEncrypt] = true
						case 's':
							keyCapabilitiesMap[KCSign] = true
						case 'c':
							keyCapabilitiesMap[KCCertify] = true
						case 'a':
							keyCapabilitiesMap[KCAuthentication] = true
						}
					}
					for _, c := range keyCapabilitiesString {
						switch c {
						case 'E', 'S', 'C', 'A':
							key.Primary = true
						}
					}
					for keyCapability := range keyCapabilitiesMap {
						key.KeyCapability = append(key.KeyCapability, keyCapability)
					}
					sort.Sort(key.KeyCapability)
					keys = append(keys, key)
				}
			} else if typeOfRecord == "fpr" && key != nil {
				key.Fingerprint = fields[9]
			} else if typeOfRecord == "uid" && key != nil {
				key.UserId = append(key.UserId, fields[9])
			} else {
				key = nil
			}
		}
	}
	var validKeys []Key
	for _, key := range keys {
		if key.Fingerprint != "" {
			validKeys = append(validKeys, *key)
		}
	}
	return validKeys, nil
}

func ListSecretKeys() ([]Key, error) {
	// "--fingerprint" x2 so that fingerprints would be printed for subkeys too
	out, err := executeInShellAndGrabOutput(gpg(), "--list-secret-keys", "--with-colons", "--fingerprint", "--fingerprint")
	// output example:
	// sec:u:4096:1:461A804F2609FD89:1495301630:::u:::scESCA:::D2760001240102010006057647860000::::
	// fpr:::::::::160A7A9CF46221A56B06AD64461A804F2609FD89:
	if err != nil {
		return nil, err
	}
	keys, err := parseKeys(out)
	if err != nil {
		return nil, err
	}
	if keyCapabilitiesMissing(keys) {
		// must be we're in gpg < 2.1 land (--list-secret-keys is missing KeyCapability data)
		publicKeys, err := ListKeys()
		if err != nil {
			return nil, err
		}
		publicKeyByFP := make(map[string]Key)
		for _, key := range publicKeys {
			publicKeyByFP[key.Fingerprint] = key
		}
		for i, key := range keys {
			if pk, ok := publicKeyByFP[key.Fingerprint]; ok && len(key.KeyCapability) == 0 {
				key.KeyCapability = pk.KeyCapability
				key.Primary = pk.Primary
				keys[i] = key
			}
		}
	}
	res := []Key{}
	for i, key := range keys {
		for _, keyCapability := range key.KeyCapability {
			if keyCapability == KCEncrypt {
				res = append(res, keys[i])
			}
		}
	}
	return res, nil
}

func keyCapabilitiesMissing(keys []Key) bool {
	for _, key := range keys {
		if len(key.KeyCapability) == 0 {
			return true
		}
	}
	return false
}

func ListKeys() ([]Key, error) {
	// "--fingerprint" x2 so that fingerprints would be printed for subkeys too
	out, err := executeInShellAndGrabOutput(gpg(), "--list-keys", "--with-colons", "--fingerprint", "--fingerprint")
	if err != nil {
		return nil, err
	}
	return parseKeys(out)
}

func EncryptAndSign(data []byte, recipient string) ([]byte, error) {
	out, err := pipeThroughGPG(data,
		"--sign", "-a", "-e", "-r", recipient, "--trusted-key", recipient[len(recipient)-16:])
	if _, ok := err.(*exec.ExitError); ok {
		hint := ""
		if log.GetLevel() != log.DebugLevel {
			hint = " (re-run with --debug flag to get more details)"
		}
		err = errors.New("Failed to encrypt/sign DEK with PGP key " + recipient + hint)
	}
	return out, err
}

func DecryptAndVerify(data []byte) ([]byte, error) {
	out, err := pipeThroughGPG(data, "-d", "--status-fd", "3")
	if _, ok := err.(*exec.ExitError); ok {
		hint := ""
		if log.GetLevel() != log.DebugLevel {
			hint = " (re-run with --debug flag to get more details)"
		}
		err = errors.New("Failed to decrypt/verify DEK" + hint)
	}
	return out, err
}

func pipeThroughGPG(content []byte, args ...string) ([]byte, error) {
	tmp, err := ioutil.TempFile("", "")
	ioutil.WriteFile(tmp.Name(), content, 0600)
	defer func() { os.Remove(tmp.Name()) }()
	defer func() { os.Remove(tmp.Name() + "E") }()
	if err != nil {
		return nil, err
	}
	if keyring != "" {
		args = append(args, "--no-default-keyring", "--keyring", keyring)
	}
	command := append([]string{gpg()}, args...)
	if err := executeInShell(append(command, "-o", tmp.Name()+"E", tmp.Name())...); err != nil {
		return nil, err
	}
	return ioutil.ReadFile(tmp.Name() + "E")
}

func executeInShell(command ...string) error {
	cmd := buildCommand(command)
	var verifySignature bool
	for _, c := range command {
		if c == "--status-fd" {
			verifySignature = true
			break
		}
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr
	if log.GetLevel() == log.DebugLevel {
		cmd.Stderr = os.Stderr
	}
	if verifySignature {
		r, w, err := os.Pipe()
		if err != nil {
			return err
		}
		cmd.ExtraFiles = []*os.File{w}
		if err := cmd.Start(); err != nil {
			return err
		}
		w.Close()
		status, err := ioutil.ReadAll(r)
		match := regexp.MustCompile("VALIDSIG ([0-9A-F]+)").FindSubmatch(status)
		if match == nil {
			return errors.New("Signature is invalid or missing")
		}
		return cmd.Wait()
	} else {
		return cmd.Run()
	}
}

func executeInShellAndGrabOutput(command ...string) ([]byte, error) {
	out, err := buildCommand(command).Output()
	if err != nil {
		return nil, errors.New("'" + command[1] + "' failed: " + err.Error())
	}
	return out, nil
}

func buildCommand(command []string) *exec.Cmd {
	var execArg []string
	// noinspection GoBoolExpressions
	if runtime.GOOS == "windows" {
		execArg = []string{"cmd", "/C"}
	} else {
		execArg = []string{"sh", "-c"}
	}
	log.Debugf(`Executing %s %s "%s"`, execArg[0], execArg[1], strings.Join(command, " "))
	return exec.Command(execArg[0], execArg[1], strings.Join(command, " "))
}
