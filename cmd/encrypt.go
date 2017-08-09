package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/shyiko/kubesec/crypto/aes"
	"github.com/shyiko/kubesec/gpg"
	"gopkg.in/yaml.v2"
	"sort"
	"strings"
)

const NS string = "# kubesec:"
const blockSize int = 48

type Key struct {
	Fingerprint           string
	EncryptedSymmetricKey []byte
}
type Keys []Key

func (f Keys) Index(fingerprint string) int {
	for i, key := range f {
		if key.Fingerprint == fingerprint {
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
	return f[i].Fingerprint < f[j].Fingerprint
}

func (f Keys) Swap(i int, j int) {
	f[i], f[j] = f[j], f[i]
}

type EncryptionContext struct {
	SymmetricKey []byte
	Keys         Keys
	Stash        map[string]interface{} // IV by data.KEY
}

func (ctx *EncryptionContext) RotateSymmetricKey() {
	ctx.SymmetricKey = nil
	var updatedKeys Keys
	for _, key := range ctx.Keys {
		key.EncryptedSymmetricKey = nil
		updatedKeys = append(updatedKeys, key)
	}
	ctx.Keys = updatedKeys
	ctx.Stash = nil
}

func IsEncrypted(resource []byte) bool {
	return strings.Index(string(resource), "\n"+NS+"v:") != -1
}

func Encrypt(resource []byte, ctx EncryptionContext) ([]byte, error) {
	rs, err := unmarshal(resource)
	if err != nil {
		return nil, err
	}
	if ctx.SymmetricKey == nil {
		for _, key := range ctx.Keys {
			if key.EncryptedSymmetricKey != nil {
				panic("Unexpected state (please report at https://github.com/shyiko/kubesec)")
			}
		}
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			return nil, err
		}
		ctx.SymmetricKey = key
	}
	cipher := aes.Cipher{}
	data := rs.data()
	for key, value := range data {
		mod := len(value) % blockSize
		if mod != 0 {
			value += strings.Repeat("\u0000", blockSize-mod)
		}
		if encryptedValue, err := cipher.Encrypt(value, ctx.SymmetricKey, key, ctx.Stash[key]); err != nil {
			return nil, err
		} else {
			data[key] = encryptedValue
		}
	}
	if ctx.Keys == nil {
		key, err := gpg.PrimaryKey()
		if err != nil {
			return nil, err // todo: improve message
		}
		ctx.Keys = []Key{{Fingerprint: key.Fingerprint}}
	}
	return marshalWithEncryptionContext(rs, ctx)
}

type resource map[interface{}]interface{}

func (rs resource) data() map[string]string {
	data := rs["data"]
	if data == nil {
		return nil
	}
	return data.(map[string]string)
}
func (rs resource) setData(data map[string]string) {
	rs["data"] = data
}

func unmarshal(rs []byte) (resource, error) {
	m := make(map[interface{}]interface{})
	yaml.Unmarshal(rs, &m)
	if m["kind"] != "Secret" {
		return nil, errors.New("kind != Secret")
	}
	if m["data"] != nil {
		data, ok := m["data"].(map[interface{}]interface{})
		if !ok {
			return nil, errors.New(`Secret's "data" isn't an object`)
		}
		dataMap := make(map[string]string)
		for k, v := range data {
			kk, kString := k.(string)
			vv, vString := v.(string)
			if !kString || !vString {
				return nil, fmt.Errorf(`Secret's "data.%v" isn't a string'`, k)
			}
			dataMap[kk] = vv
		}
		m["data"] = dataMap
	}
	return m, nil
}

func marshal(rs resource) ([]byte, error) {
	return yaml.Marshal(rs)
}

func marshalWithEncryptionContext(rs resource, ctx EncryptionContext) ([]byte, error) {
	footer := []string{NS + "v:1\n"}
	sort.Sort(ctx.Keys)
	for _, pgp := range ctx.Keys {
		if pgp.EncryptedSymmetricKey == nil {
			encryptedSymmetricKey, err := gpg.EncryptAndSign(ctx.SymmetricKey, pgp.Fingerprint)
			if err != nil {
				return nil, err
			}
			pgp.EncryptedSymmetricKey = encryptedSymmetricKey
		}
		escapedEncryptedSymmetricKey := base64.StdEncoding.EncodeToString(pgp.EncryptedSymmetricKey)
		footer = append(footer, NS+"pgp:"+pgp.Fingerprint+":"+string(escapedEncryptedSymmetricKey)+"\n")
	}
	body, err := yaml.Marshal(rs)
	if err != nil {
		return nil, err
	}
	return append(body, []byte(strings.Join(footer, ""))...), nil
}

type KeySet struct {
	Replace bool
	Add     []string
	Remove  []string
}

func EncryptWithKeySet(resource []byte, keySet KeySet) ([]byte, error) {
	ctx := &EncryptionContext{}
	if IsEncrypted(resource) {
		var err error
		resource, ctx, err = Decrypt(resource)
		if err != nil {
			return nil, err
		}
		if keySet.Replace {
			if len(ctx.Keys) != 0 {
				for _, key := range keySet.Add {
					if ctx.Keys.Index(key) == -1 {
						ctx.RotateSymmetricKey()
						ctx.Keys = Keys{}
						break
					}
				}
			}
		}
	}
	for _, key := range keySet.Add {
		if ctx.Keys.Index(key) == -1 {
			ctx.Keys = append(ctx.Keys, Key{Fingerprint: key})
		}
	}
	var keyRemoved bool
	for _, key := range keySet.Remove {
		if i := ctx.Keys.Index(key); i != -1 {
			ctx.Keys = append(ctx.Keys[:i], ctx.Keys[i+1:]...)
			keyRemoved = true
		}
	}
	if keyRemoved {
		ctx.RotateSymmetricKey()
	}
	return Encrypt(resource, *ctx)
}
