package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	awskms "github.com/shyiko/kubesec/aws/kms"
	"github.com/shyiko/kubesec/crypto/aes"
	googlecloudkms "github.com/shyiko/kubesec/gcp/kms"
	"github.com/shyiko/kubesec/gpg"
	log "github.com/sirupsen/logrus"
)

func Decrypt(resource []byte) ([]byte, *EncryptionContext, error) {
	rs, ctx, err := decrypt(resource, false)
	if err != nil {
		return nil, nil, err
	}
	if !ctx.IsEmpty() {
		if err := validateMAC(rs, *ctx); err != nil {
			return nil, nil, err
		}
	}
	output, err := marshal(rs)
	return output, ctx, err
}

func DecryptCleartext(resource []byte) ([]byte, *EncryptionContext, error) {
	plaintext, ctx, err := Decrypt(resource)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err = transform(plaintext, decodeBase64Data)
	return plaintext, ctx, err
}

func decrypt(resource []byte, ignoreMissingMAC bool) (resource, *EncryptionContext, error) {
	rs, err := unmarshal(resource)
	if err != nil {
		return nil, nil, err
	}
	ctx := &EncryptionContext{}
	data := rs.data()
	stringData := rs.stringData()
	if len(data) != 0 || len(stringData) != 0 {
		ctx, err = reconstructEncryptionContext(resource, true, ignoreMissingMAC)
		if err != nil {
			return nil, nil, err
		}
		cipher := aes.Cipher{}
		for _, c := range []struct {
			path string
			data map[string]string
		}{
			{"data", data},
			{"stringData", stringData},
		} {
			for key, value := range c.data {
				if decryptedValue, stash, err := cipher.Decrypt(value, ctx.DEK, []byte(key)); err == nil {
					padding := strings.Index(decryptedValue, "\u0000")
					if padding != -1 {
						decryptedValue = decryptedValue[:padding]
					}
					c.data[key] = decryptedValue
					ctx.Stash[fmt.Sprintf("%s.%s", c.path, key)] = stash
				} else {
					return nil, nil, fmt.Errorf(`Failed to decrypt Secret's "%s.%s"`, c.path, key)
				}
			}
		}
	}
	return rs, ctx, err
}

func reconstructEncryptionContext(resource []byte, decryptDEK bool, ignoreMissingMAC bool) (*EncryptionContext, error) {
	loadPGPKey := lazyLoadPGPKey()
	ctx := EncryptionContext{Stash: make(map[string]interface{})}
	var v string
	for i, line := range strings.Split(string(resource), "\n") {
		if strings.HasPrefix(line, NS) {
			split := strings.Split(line[len(NS):], ":")
			if len(split) < 2 {
				return nil, errors.New(fmt.Sprintf("Unexpected value (line %v)", i+1))
			}
			switch split[0] + ":" {
			case NSVersion:
				v = split[1]
				if !IsVersionSupported(v) {
					return nil, errors.New(fmt.Sprintf(
						"It appears that Secret was encrypted with newer version of kubesec.\n" +
							"Visit https://github.com/shyiko/kubesec for upgrade instructions.",
					))
				}
			case NSPGP:
				loadPGPKey(i+1, &ctx, decryptDEK, split[1:])
			case NSGCPKMS:
				loadGCPKMSKey(i+1, &ctx, decryptDEK, split[1:])
			case NSAWSKMS:
				loadAWSKMSKey(i+1, &ctx, decryptDEK, split[1:])
			case NSMAC:
				ctx.MAC = split[1]
			default:
				return nil, errors.New(fmt.Sprintf("Unexpected value (line %v)", i+1))
			}
		}
	}
	if decryptDEK && ctx.DEK == nil {
		if IsEncrypted(resource) {
			hint := ""
			if log.GetLevel() != log.DebugLevel {
				hint = " (re-run with --debug flag to get more details)"
			}
			return nil, errors.New("Unable to decrypt Data Encryption Key (DEK)" + hint)
		}
		return nil, errors.New("Secret isn't encrypted")
	}
	if !ignoreMissingMAC && ctx.MAC == "" {
		if v == version || v == versionWithAWSKMSAndGCPKMSSupport {
			return nil, errors.New(
				"It appears that Secret was encrypted with older version of kubesec (MAC is missing).\n" +
					"Use `kubesec edit -i --recompute-mac <file>` to review & confirm content of the Secret.",
			)
		} else {
			return nil, errors.New("MAC is missing")
		}
	}
	return &ctx, nil
}

func lazyLoadPGPKey() func(lineNumber int, ctx *EncryptionContext, decryptDEK bool, args []string) error {
	var gpgSecretKeys []gpg.Key
	return func(lineNumber int, ctx *EncryptionContext, decryptDEK bool, args []string) error {
		var err error
		if gpgSecretKeys == nil {
			if gpgSecretKeys, err = gpg.ListSecretKeys(); err != nil {
				return err
			}
		}
		return loadPGPKey(lineNumber, ctx, decryptDEK, args, gpgSecretKeys)
	}
}

func loadPGPKey(lineNumber int, ctx *EncryptionContext, decryptDEK bool, args []string, gpgSecretKeys []gpg.Key) error {
	// <ns>:<fingerprint>:<base64-encoded encrypted DEK (with signature)>
	if len(args) != 2 {
		return errors.New(fmt.Sprintf("Unexpected value (line %v)", lineNumber))
	}
	fingerprint, base64EncodedEncryptedDEK := args[0], args[1]
	encryptedDEK, err := base64.StdEncoding.DecodeString(base64EncodedEncryptedDEK)
	if err != nil {
		return err
	}
	key := KeyWithDEK{Key{Type: KTPGP, Id: fingerprint}, encryptedDEK}
	ctx.Keys = append(ctx.Keys, key)
	if decryptDEK && ctx.DEK == nil {
		if gpgSecretKeys == nil {
			gpgSecretKeys, err = gpg.ListSecretKeys()
			if err != nil {
				return err
			}
		}
		for _, secretKey := range gpgSecretKeys {
			if secretKey.Fingerprint == key.Id {
				if log.GetLevel() == log.DebugLevel {
					log.Debugf("Attempting to decrypt DEK with PGP key %v", key.Id)
				}
				var err error
				ctx.DEK, err = gpg.DecryptAndVerify(key.EncryptedDEK)
				if err != nil && log.GetLevel() == log.DebugLevel {
					log.Debugf("Unable to decrypt DEK with PGP key %v (%v)", key.Id, err)
				}
			}
		}
	}
	return nil
}

func loadGCPKMSKey(lineNumber int, ctx *EncryptionContext, decryptDEK bool, args []string) error {
	// <ns>:...:<base64-encoded encrypted DEK>
	if len(args) < 2 {
		return errors.New(fmt.Sprintf("Unexpected value (line %v)", lineNumber))
	}
	base64EncodedEncryptedDEK := args[len(args)-1]
	encryptedDEK, err := base64.StdEncoding.DecodeString(base64EncodedEncryptedDEK)
	if err != nil {
		return err
	}
	key := KeyWithDEK{
		Key{Type: KTGCPKMS, Id: strings.Join(args[:len(args)-1], ":")},
		encryptedDEK,
	}
	ctx.Keys = append(ctx.Keys, key)
	if decryptDEK && ctx.DEK == nil {
		if log.GetLevel() == log.DebugLevel {
			log.Debugf("Attempting to decrypt DEK with GCP KMS key %v", key.Id)
		}
		client, err := googlecloudkms.New()
		if err != nil {
			return err
		}
		ctx.DEK, err = client.Decrypt(key.Id, key.EncryptedDEK)
		if err != nil && log.GetLevel() == log.DebugLevel {
			log.Debugf("Unable to decrypt DEK with GCP KMS key %v (%v)", key.Id, err)
		}
	}
	return nil
}

func loadAWSKMSKey(lineNumber int, ctx *EncryptionContext, decryptDEK bool, args []string) error {
	// <ns>:...:<base64-encoded encrypted DEK>
	if len(args) < 2 {
		return errors.New(fmt.Sprintf("Unexpected value (line %v)", lineNumber))
	}
	base64EncodedEncryptedDEK := args[len(args)-1]
	encryptedDEK, err := base64.StdEncoding.DecodeString(base64EncodedEncryptedDEK)
	if err != nil {
		return err
	}
	key := KeyWithDEK{
		Key{Type: KTAWSKMS, Id: strings.Join(args[:len(args)-1], ":")},
		encryptedDEK,
	}
	ctx.Keys = append(ctx.Keys, key)
	if decryptDEK && ctx.DEK == nil {
		if log.GetLevel() == log.DebugLevel {
			log.Debugf("Attempting to decrypt DEK with AWS KMS key %v", key.Id)
		}
		client, err := awskms.New()
		if err != nil {
			return err
		}
		ctx.DEK, err = client.Decrypt(key.Id, key.EncryptedDEK)
		if err != nil && log.GetLevel() == log.DebugLevel {
			log.Debugf("Unable to decrypt DEK with AWS KMS key %v (%v)", key.Id, err)
		}
	}
	return nil
}
