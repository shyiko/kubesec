package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	awskms "github.com/shyiko/kubesec/aws/kms"
	"github.com/shyiko/kubesec/crypto/aes"
	googlecloudkms "github.com/shyiko/kubesec/gcp/kms"
	"github.com/shyiko/kubesec/gpg"
	"gopkg.in/yaml.v2"
	"regexp"
	"sort"
	"strings"
)

// "value"s are padded to a block size to avoid leaking length information
const blockSize = 48

const version = "1"
const versionWithAWSKMSAndGCPKMSSupport = "2"
const versionWithMAC = "3"
const versionWithStringDataSupport = "4"

func IsVersionSupported(v string) bool {
	return v == version ||
		v == versionWithAWSKMSAndGCPKMSSupport ||
		v == versionWithMAC ||
		v == versionWithStringDataSupport
}

type Key struct {
	Type KeyType
	Id   string // fingerprint in case of PGP, arn:... in case of aws-kms, projects/... in case of gcp-kms, etc.
}

var PGPFingerprintRegexp = regexp.MustCompile("[a-zA-Z0-9]{16,}")

func NewKey(key string) (*Key, error) {
	switch {
	case strings.HasPrefix(key, NSGCPKMS) || strings.HasPrefix(key, "projects/"):
		return &Key{KTGCPKMS, strings.TrimPrefix(key, NSGCPKMS)}, nil
	case strings.HasPrefix(key, NSAWSKMS) || strings.HasPrefix(key, "arn:"):
		return &Key{KTAWSKMS, strings.TrimPrefix(key, NSAWSKMS)}, nil
	case strings.HasPrefix(key, NSPGP) || PGPFingerprintRegexp.MatchString(key):
		fingerprint := strings.TrimPrefix(key, NSPGP)
		if fingerprint == "default" {
			primaryPGPKey, err := gpg.PrimaryKey()
			if err != nil {
				return nil, err
			}
			fingerprint = primaryPGPKey.Fingerprint
		}
		if len(fingerprint) < 16 {
			return nil, fmt.Errorf("Malformed PGP key - %v", key)
		}
		return &Key{KTPGP, fingerprint}, nil
	default:
		return nil, fmt.Errorf("Unrecognized type of key - %v", key)
	}
}

type KeyWithDEK struct {
	Key
	EncryptedDEK []byte
}

type KeyType int

const (
	KTPGP KeyType = iota
	KTGCPKMS
	KTAWSKMS
)

var KeyTypes = []KeyType{
	KTPGP,
	KTGCPKMS,
	KTAWSKMS,
}

const (
	NS        = "# kubesec:"
	NSVersion = "v:"   // v:<version>
	NSMAC     = "mac:" // mac:<mac>
)

const (
	NSPGP    = "pgp:" // pgp:<fingerprint>:<base64-encoded encrypted DEK (with signature)>
	NSGCPKMS = "gcp:" // gcp:...:<base64-encoded encrypted DEK>
	NSAWSKMS = "aws:" // aws:...:<base64-encoded encrypted DEK>
)

func nsByKeyType(keyType KeyType) string {
	switch keyType {
	case KTPGP:
		return NSPGP
	case KTGCPKMS:
		return NSGCPKMS
	case KTAWSKMS:
		return NSAWSKMS
	default:
		panic(fmt.Sprintf("Unexpected Key.Type %v", keyType))
	}
}

type Keys []KeyWithDEK

func (f Keys) Index(lookupKey Key) int {
	for i, key := range f {
		if key.Type == lookupKey.Type && key.Id == lookupKey.Id {
			return i
		}
	}
	return -1
}

func (f Keys) IndexByType(keyType KeyType) int {
	for i, key := range f {
		if key.Type == keyType {
			return i
		}
	}
	return -1
}

// sort.Interface

func (f Keys) Len() int {
	return len(f)
}

func (f Keys) Less(i int, j int) bool {
	return f[i].Type < f[j].Type && f[i].Id < f[j].Id
}

func (f Keys) Swap(i int, j int) {
	f[i], f[j] = f[j], f[i]
}

type EncryptionContext struct {
	DEK   []byte
	Keys  Keys
	Stash map[string]interface{} // IV by data.KEY
	MAC   string
}

func (ctx *EncryptionContext) RotateDEK() {
	ctx.DEK = nil
	var updatedKeys Keys
	for _, key := range ctx.Keys {
		key.EncryptedDEK = nil
		updatedKeys = append(updatedKeys, key)
	}
	ctx.Keys = updatedKeys
	ctx.Stash = nil
}

func (ctx *EncryptionContext) IsEmpty() bool {
	return len(ctx.DEK) == 0 && len(ctx.Keys) == 0
}

func IsEncrypted(resource []byte) bool {
	return strings.Index(string(resource), "\n"+NS+NSVersion) != -1
}

func EncryptWithContext(resource []byte, ctx EncryptionContext) ([]byte, error) {
	rs, err := unmarshal(resource)
	if err != nil {
		return nil, err
	}
	if ctx.DEK == nil {
		for _, key := range ctx.Keys {
			if key.EncryptedDEK != nil {
				panic("Unexpected state (please report at https://github.com/shyiko/kubesec)")
			}
		}
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return nil, err
		}
		ctx.DEK = key
	}
	if ctx.Keys == nil {
		primaryKey, err := gpg.PrimaryKey()
		if err != nil {
			return nil, err
		}
		ctx.Keys = []KeyWithDEK{{Key{Id: primaryKey.Fingerprint}, nil}}
	}
	ctx.MAC = computeMAC(rs, ctx)
	data := rs.data()
	for key, value := range data {
		if _, err := base64.StdEncoding.DecodeString(value); err != nil {
			return nil, fmt.Errorf(`data.%s value is not base64-encoded (either base64-encode data.* values or use --cleartext)`, key)
		}
	}
	encryptData("data", data, ctx)
	encryptData("stringData", rs.stringData(), ctx)
	return marshalWithEncryptionContext(rs, ctx)
}

func encryptData(path string, data map[string]string, ctx EncryptionContext) error {
	cipher := aes.Cipher{}
	for key, value := range data {
		mod := len(value) % blockSize
		if mod != 0 {
			value += strings.Repeat("\u0000", blockSize-mod)
		}
		if encryptedValue, err := cipher.Encrypt(value, ctx.DEK, []byte(key), ctx.Stash[fmt.Sprintf("%s.%s", path, key)]); err != nil {
			return err
		} else {
			data[key] = encryptedValue
		}
	}
	return nil
}

type resource map[interface{}]interface{}

func computeMAC(rs resource, ctx EncryptionContext) string {
	aad := gatherAdditionalAuthenticatedDataForMAC(rs, ctx)
	if ctx.MAC != "" {
		// return same mac if hash hasn't changed
		_, _, err := aes.Cipher{}.Decrypt(ctx.MAC, ctx.DEK, aad)
		if err == nil {
			return ctx.MAC
		}
	}
	mac, err := aes.Cipher{}.Encrypt("", ctx.DEK, aad, nil)
	if err != nil {
		panic(err)
	}
	return mac
}

func gatherAdditionalAuthenticatedDataForMAC(rs resource, ctx EncryptionContext) []byte {
	var hash bytes.Buffer
	writeMap(&hash, rs.data())
	writeMap(&hash, rs.stringData())
	sortedKeys := ctx.Keys[:]
	sort.Sort(sortedKeys)
	for _, key := range sortedKeys {
		hash.Write([]byte(key.Id))
	}
	return hash.Bytes()
}

func writeMap(hash *bytes.Buffer, data map[string]string) {
	sortedDataKeys := make([]string, 0, len(data))
	for key := range data {
		sortedDataKeys = append(sortedDataKeys, key)
	}
	sort.Strings(sortedDataKeys)
	for _, key := range sortedDataKeys {
		hash.Write([]byte(key))
		hash.Write([]byte(data[key]))
	}
}

func validateMAC(rs resource, ctx EncryptionContext) error {
	aad := gatherAdditionalAuthenticatedDataForMAC(rs, ctx)
	_, _, err := aes.Cipher{}.Decrypt(ctx.MAC, ctx.DEK, aad)
	if err != nil {
		return errors.New("MACs don't match.\n" +
			"Use `kubesec edit -i --recompute-mac <file>` to review & confirm content of the Secret.")
	}
	return nil
}

func (rs resource) data() map[string]string {
	data := rs["data"]
	if data == nil {
		return nil
	}
	return data.(map[string]string)
}
func (rs resource) setData(data map[string]string) {
	if len(data) != 0 {
		rs["data"] = data
	} else {
		delete(data, "data")
	}
}
func (rs resource) stringData() map[string]string {
	data := rs["stringData"]
	if data == nil {
		return nil
	}
	return data.(map[string]string)
}
func (rs resource) setStringData(data map[string]string) {
	if len(data) != 0 {
		rs["stringData"] = data
	} else {
		delete(data, "stringData")
	}
}

func unmarshal(rs []byte) (resource, error) {
	m := make(map[interface{}]interface{})
	yaml.Unmarshal(rs, &m)
	if m["kind"] != "Secret" {
		return nil, errors.New("kind != Secret")
	}
	if err := unmarshalData("data", m); err != nil {
		return nil, err
	}
	if err := unmarshalData("stringData", m); err != nil {
		return nil, err
	}
	return m, nil
}

func unmarshalData(path string, m map[interface{}]interface{}) error {
	if m[path] != nil {
		data, ok := m[path].(map[interface{}]interface{})
		if !ok {
			return fmt.Errorf(`Secret's "%s" isn't an object`, path)
		}
		dataMap := make(map[string]string)
		for k, v := range data {
			kk, kString := k.(string)
			vv, vString := v.(string)
			if !kString || !vString {
				return fmt.Errorf(`Secret's "%s.%v" isn't a string`, path, k)
			}
			dataMap[kk] = vv
		}
		m[path] = dataMap
	}
	return nil
}

func marshal(rs resource) ([]byte, error) {
	return yaml.Marshal(rs)
}

func marshalWithEncryptionContext(rs resource, ctx EncryptionContext) ([]byte, error) {
	ver := versionWithMAC
	if len(rs.stringData()) != 0 {
		ver = versionWithStringDataSupport
	}
	footer := []string{NS + NSVersion + ver + "\n"}
	sort.Sort(ctx.Keys)
	for _, key := range ctx.Keys {
		if key.EncryptedDEK == nil {
			encryptedDEK, err := encrypt(key.Key, ctx.DEK)
			if err != nil {
				return nil, err
			}
			key.EncryptedDEK = encryptedDEK
		}
		base64EncodedEncryptedDEK := base64.StdEncoding.EncodeToString(key.EncryptedDEK)
		footer = append(footer, NS+nsByKeyType(key.Type)+key.Id+":"+string(base64EncodedEncryptedDEK)+"\n")
	}
	body, err := marshal(rs)
	if err != nil {
		return nil, err
	}
	footer = append(footer, NS+NSMAC+ctx.MAC+"\n")
	return append(body, []byte(strings.Join(footer, ""))...), nil
}

func encrypt(key Key, data []byte) ([]byte, error) {
	switch key.Type {
	case KTPGP:
		return gpg.EncryptAndSign(data, key.Id)
	case KTGCPKMS:
		client, err := googlecloudkms.New()
		if err != nil {
			return nil, err
		}
		return client.Encrypt(key.Id, data)
	case KTAWSKMS:
		client, err := awskms.New()
		if err != nil {
			return nil, err
		}
		return client.Encrypt(key.Id, data)
	default:
		return nil, fmt.Errorf("Unrecognized key %s", key.Id)
	}
}

type KeySetMutation struct {
	Replace bool
	Add     []Key
	Remove  []Key
	Parent  []byte
}

func (ks KeySetMutation) IsEmpty() bool {
	return !ks.Replace && len(ks.Add) == 0 && len(ks.Remove) == 0
}

func (ks KeySetMutation) applyTo(ctx *EncryptionContext) {
	if ks.Replace {
		if len(ctx.Keys) != 0 {
			for _, key := range ks.Add {
				if ctx.Keys.Index(key) == -1 {
					ctx.RotateDEK()
					ctx.Keys = Keys{}
					break
				}
			}
		}
	}
	for _, key := range ks.Add {
		if ctx.Keys.Index(key) == -1 {
			ctx.Keys = append(ctx.Keys, KeyWithDEK{key, nil})
		}
	}
	var keyRemoved bool
	for _, key := range ks.Remove {
		if i := ctx.Keys.Index(key); i != -1 {
			ctx.Keys = append(ctx.Keys[:i], ctx.Keys[i+1:]...)
			keyRemoved = true
		}
	}
	if keyRemoved {
		ctx.RotateDEK()
	}
}

func Encrypt(resource []byte, mutation KeySetMutation) ([]byte, error) {
	return encryptWithKeySet(resource, mutation, false)
}

func EncryptCleartext(resource []byte, mutation KeySetMutation) ([]byte, error) {
	return encryptWithKeySet(resource, mutation, true)
}

func encryptWithKeySet(resource []byte, mutation KeySetMutation, cleartext bool) ([]byte, error) {
	var err error
	var ctx *EncryptionContext
	if mutation.Parent != nil {
		// decrypt instead of reconstructEncryptionContext so that ctx.Stash would be populated
		_, ctx, err = decrypt(mutation.Parent, false)
		if err != nil {
			return nil, err
		}
	} else {
		ctx = &EncryptionContext{}
	}
	if IsEncrypted(resource) {
		resource, ctx, err = Decrypt(resource)
		if err != nil {
			return nil, err
		}
	}
	if cleartext {
		resource, err = transform(resource, encodeDataToBase64)
		if err != nil {
			return nil, err
		}
	}
	mutation.applyTo(ctx)
	return EncryptWithContext(resource, *ctx)
}
