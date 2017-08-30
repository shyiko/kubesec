package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	awskms "github.com/shyiko/kubesec/aws/kms"
	"github.com/shyiko/kubesec/crypto/aes"
	googlecloudkms "github.com/shyiko/kubesec/gcp/kms"
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
			if decryptedValue, stash, err := cipher.Decrypt(value, ctx.DEK, key); err == nil {
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

func reconstructEncryptionContext(resource []byte, decryptDEK bool) (*EncryptionContext, error) {
	loadPGPKey := lazyLoadPGPKey()
	ctx := EncryptionContext{Stash: make(map[string]interface{})}
	for i, line := range strings.Split(string(resource), "\n") {
		if strings.HasPrefix(line, NS) {
			split := strings.Split(line[len(NS):], ":")
			if len(split) < 2 {
				return nil, errors.New(fmt.Sprintf("Unexpected value (line %v)", i+1))
			}
			switch split[0] + ":" {
			case NSVersion:
				if !IsVersionSupported(split[1]) {
					return nil, errors.New(fmt.Sprintf(
						"Secret was encrypted with a newer version of kubesec (https://github.com/shyiko/kubesec)",
					))
				}
			case NSPGP:
				loadPGPKey(i+1, &ctx, decryptDEK, split[1:])
			case NSGCPKMS:
				loadGCPKMSKey(i+1, &ctx, decryptDEK, split[1:])
			case NSAWSKMS:
				loadAWSKMSKey(i+1, &ctx, decryptDEK, split[1:])
			default:
				return nil, errors.New(fmt.Sprintf("Unexpected value (line %v)", i+1))
			}
		}
	}
	if decryptDEK && ctx.DEK == nil {
		if IsEncrypted(resource) {
			return nil, errors.New("Unable to decrypt Data Encryption Key (DEK)")
		}
		return nil, errors.New("\"data\" isn't encrypted")
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
