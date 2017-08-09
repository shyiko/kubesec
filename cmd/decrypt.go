package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/shyiko/kubesec/crypto/aes"
	"github.com/shyiko/kubesec/gpg"
	"strings"
)

func Decrypt(resource []byte) ([]byte, *EncryptionContext, error) {
	rs, err := unmarshal(resource)
	if err != nil {
		return nil, nil, err
	}
	data := rs.data()
	ctx := &EncryptionContext{}
	if len(data) != 0 {
		ctx, err = reconstructEncryptionContext(resource, true)
		if err != nil {
			return nil, nil, err
		}
		cipher := aes.Cipher{}
		for key, value := range data {
			if decryptedValue, stash, err := cipher.Decrypt(value, ctx.SymmetricKey, key); err == nil {
				padding := strings.Index(decryptedValue, "\u0000")
				if padding != -1 {
					decryptedValue = decryptedValue[:padding]
				}
				data[key] = decryptedValue
				ctx.Stash[key] = stash
			} else {
				return nil, nil, fmt.Errorf(`Failed to decrypt Secret's "data.%v"`, key)
			}
		}
	}
	output, err := marshal(rs)
	return output, ctx, err
}

func reconstructEncryptionContext(resource []byte, decryptSymmetricKey bool) (*EncryptionContext, error) {
	secretKeys, err := gpg.ListSecretKeys()
	if err != nil {
		return nil, err
	}
	ctx := EncryptionContext{Stash: make(map[string]interface{})}
	for i, line := range strings.Split(string(resource), "\n") {
		if strings.HasPrefix(line, NS) {
			split := strings.Split(line[len(NS):], ":")
			if len(split) < 3 {
				return nil, errors.New(fmt.Sprintf("Unexpected value (line %v)", i+1))
			}
			switch split[0] {
			case "pgp":
				fingerprint, escapedEncryptedSymmetricKey := split[1], split[2]
				encryptedSymmetricKey, err := base64.StdEncoding.DecodeString(escapedEncryptedSymmetricKey)
				if err != nil {
					return nil, err
				}
				key := Key{Fingerprint: fingerprint, EncryptedSymmetricKey: encryptedSymmetricKey}
				ctx.Keys = append(ctx.Keys, key)
				if decryptSymmetricKey {
					for _, secretKey := range secretKeys {
						if secretKey.Fingerprint == key.Fingerprint {
							var err error
							ctx.SymmetricKey, err = gpg.DecryptAndVerify(key.EncryptedSymmetricKey)
							if err != nil {
								return nil, err
							}
						}
					}
				}
			default:
				return nil, errors.New(fmt.Sprintf("Unexpected value (line %v)", i+1))
			}
		}
	}
	if decryptSymmetricKey && ctx.SymmetricKey == nil {
		return nil, errors.New("PGP key required to decrypt the data wasn't found")
	}
	return &ctx, nil
}
