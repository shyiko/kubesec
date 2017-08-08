// original version (licensed under Mozilla Public License Version 2.0) can be found at
// https://github.com/mozilla/sops/blob/master/aes/decryptor.go (f52dc0008daab2938b7f7ce7d54b90a882a1dc65)
package aes

import (
	cryptoaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const gcmNonceSize = 12 // go/src/crypto/cipher/gcm.go (gcmStandardNonceSize)

type Cipher struct{}

type encryptedValue struct {
	data []byte
	iv   []byte
	tag  []byte
}

type stashedValue struct {
	iv        []byte
	plaintext string
}

func (c Cipher) Decrypt(value string, key []byte, path string) (plaintext string, stash interface{}, err error) {
	if value == "" {
		return "", nil, nil
	}
	encryptedValue, err := parse(value)
	if err != nil {
		return "", nil, err
	}
	aescipher, err := cryptoaes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}
	gcm, err := cipher.NewGCM(aescipher)
	if err != nil {
		return "", nil, err
	}
	stashValue := stashedValue{iv: encryptedValue.iv}
	data := append(encryptedValue.data, encryptedValue.tag...)
	decryptedBytes, err := gcm.Open(nil, encryptedValue.iv, data, []byte(path))
	if err != nil {
		return "", nil, fmt.Errorf("Could not decrypt with AES_GCM: %s", err)
	}
	decryptedValue := string(decryptedBytes)
	stashValue.plaintext = decryptedValue
	return decryptedValue, stashValue, nil
}

func parse(value string) (*encryptedValue, error) {
	chunks := strings.Split(value, ".")
	if len(chunks) != 3 {
		return nil, fmt.Errorf("Unrecognized format of %s", value)
	}
	data, err := base64.StdEncoding.DecodeString(chunks[0])
	if err != nil {
		return nil, fmt.Errorf("Error base64-decoding data: %s", err)
	}
	iv, err := base64.StdEncoding.DecodeString(chunks[1])
	if err != nil {
		return nil, fmt.Errorf("Error base64-decoding iv: %s", err)
	}
	if len(iv) != gcmNonceSize { // go/src/crypto/cipher/gcm.go (gcmStandardNonceSize)
		return nil, fmt.Errorf("Unexpected iv: %s", err)
	}
	tag, err := base64.StdEncoding.DecodeString(chunks[2])
	if err != nil {
		return nil, fmt.Errorf("Error base64-decoding tag: %s", err)
	}
	return &encryptedValue{data, iv, tag}, nil
}

func (c Cipher) Encrypt(value string, key []byte, path string, stash interface{}) (string, error) {
	if value == "" {
		return "", nil
	}
	aescipher, err := cryptoaes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Could not initialize AES cipher: %s", err)
	}
	var iv []byte
	if stash, ok := stash.(stashedValue); !ok || stash.plaintext != value {
		iv = make([]byte, gcmNonceSize)
		_, err = rand.Read(iv)
		if err != nil {
			return "", fmt.Errorf("Could not generate random bytes for IV: %s", err)
		}
	} else {
		iv = stash.iv
	}
	gcm, err := cipher.NewGCM(aescipher)
	if err != nil {
		return "", fmt.Errorf("Could not create GCM: %s", err)
	}
	out := gcm.Seal(nil, iv, []byte(value), []byte(path))
	data, tag := out[:len(out)-cryptoaes.BlockSize], out[len(out)-cryptoaes.BlockSize:]
	return strings.Join(
		[]string{
			base64.StdEncoding.EncodeToString(data),
			base64.StdEncoding.EncodeToString(iv),
			base64.StdEncoding.EncodeToString(tag),
		},
		"."), nil
}
