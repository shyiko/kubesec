package kms

import (
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"strings"
)

type KMSClient struct {
	svc *kms.KMS
}

func New() (*KMSClient, error) {
	ctx, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}
	if log.GetLevel() == log.DebugLevel {
		log.Debugf("AWS KMS shared config region is %v", *ctx.Config.Region)
	}
	return &KMSClient{kms.New(ctx)}, nil
}

func (client *KMSClient) svcByKey(key string) (*kms.KMS, error) {
	if strings.HasPrefix(key, "arn:aws:kms:") {
		region := strings.Split(key, ":")[3]
		if *client.svc.Config.Region != region {
			ctx, err := session.NewSession(&aws.Config{Region: aws.String(region)})
			if err != nil {
				return nil, err
			}
			return kms.New(ctx), nil
		}
	}
	return client.svc, nil
}

func (client *KMSClient) Encrypt(key string, plaintext []byte) ([]byte, error) {
	svc, err := client.svcByKey(key)
	if err != nil {
		return nil, err
	}
	res, err := svc.Encrypt(&kms.EncryptInput{
		KeyId:     aws.String(key),
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, err
	}
	return res.CiphertextBlob, nil
}

func (client *KMSClient) Decrypt(key string, ciphertext []byte) ([]byte, error) {
	svc, err := client.svcByKey(key)
	if err != nil {
		return nil, err
	}
	res, err := svc.Decrypt(&kms.DecryptInput{
		CiphertextBlob: ciphertext,
	})
	if err != nil {
		return nil, err
	}
	return res.Plaintext, nil
}
