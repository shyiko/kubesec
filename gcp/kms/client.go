package kms

import (
	"encoding/base64"
	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
)

type CloudKMSClient struct {
	svc *cloudkms.Service
}

func New() (*CloudKMSClient, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	svc, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}
	return &CloudKMSClient{svc}, nil
}

func (client *CloudKMSClient) Encrypt(keyResourceID string, plaintext []byte) ([]byte, error) {
	res, err := client.svc.Projects.Locations.KeyRings.CryptoKeys.Encrypt(keyResourceID, &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(res.Ciphertext)
}

func (client *CloudKMSClient) Decrypt(keyResourceID string, ciphertext []byte) ([]byte, error) {
	res, err := client.svc.Projects.Locations.KeyRings.CryptoKeys.Decrypt(keyResourceID, &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(res.Plaintext)
}
