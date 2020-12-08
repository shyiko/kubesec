package kms

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type credentialsConfig struct {
	// The access key if static credentials are being used
	AccessKey string

	// The secret key if static credentials are being used
	SecretKey string

	// The session token if it is being used
	SessionToken string

	// If specified, the region will be provided to the config of the
	// EC2RoleProvider's client. This may be useful if you want to e.g. reuse
	// the client elsewhere.
	Region string

	// The filename for the shared credentials provider, if being used
	Filename string

	// The profile for the shared credentials provider, if being used
	Profile string
}

// KMSClient - struct used by methods within this module
type KMSClient struct {
	svc *kms.KMS
}

// GenerateCredentialChain - Restructures the request provider chain to include the webIdentityProvider
// Most of this came from here:
// https://github.com/hashicorp/vault/blob/10c0adad72fe189470a1e23cf01ef753c3f11fe4/builtin/credential/aws/client.go
// https://github.com/hashicorp/vault/blob/10c0adad72fe189470a1e23cf01ef753c3f11fe4/sdk/helper/awsutil/generate_credentials.go
// This method processes inputs for the various credential providers we'll be using.
func (c *credentialsConfig) GenerateCredentialChain() (*credentials.Credentials, error) {
	var providers []credentials.Provider

	switch {
	case c.AccessKey != "" && c.SecretKey != "":
		// Add the static credential provider
		providers = append(providers, &credentials.StaticProvider{
			Value: credentials.Value{
				AccessKeyID:     c.AccessKey,
				SecretAccessKey: c.SecretKey,
				SessionToken:    c.SessionToken,
			}})
		log.Printf("Added static credential provider. Access Key: %v", c.AccessKey)
	case c.AccessKey == "" && c.SecretKey == "":

	default: // Have one or the other but not both or neither
		return nil, fmt.Errorf("static AWS client credentials haven't been properly configured")
	}

	roleArn := os.Getenv("AWS_ROLE_ARN")
	tokenPath := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	sessionName := os.Getenv("KUBESEC_SESSION_NAME")
	if roleArn != "" && tokenPath != "" {
		if log.GetLevel() == log.DebugLevel {
			log.Debugf("AWS KMS role and token are %v, %v", roleArn, tokenPath)
			log.Debugf("Added web identity provider. Role ARN: %v", roleArn)
		}
		sess, err := session.NewSession()
		if err != nil {
			return nil, errors.Wrap(err, "error creating a new session to create a WebIdentityRoleProvider")
		}
		webIdentityProvider := stscreds.NewWebIdentityRoleProvider(sts.New(sess), roleArn, sessionName, tokenPath)

		providers = append(providers, webIdentityProvider)
	}

	providers = append(providers, &credentials.EnvProvider{})

	creds := credentials.NewChainCredentials(providers)
	if creds == nil {
		return nil, fmt.Errorf("could not compile valid credential providers from static config, environment, shared, web identity or instance metadata")
	}

	return creds, nil
}

// New - creates a session using supplied credentials
func New() (*KMSClient, error) {
	region := os.Getenv("AWS_DEFAULT_REGION")
	credsConfig := &credentialsConfig{}
	creds, err := credsConfig.GenerateCredentialChain()
	if err != nil {
		return nil, err
	}
	sess, err := session.NewSession()

	if log.GetLevel() == log.DebugLevel {
		log.Debugf("AWS KMS shared config region is %v", region)
	}

	return &KMSClient{kms.New(sess, &aws.Config{Region: aws.String(region), Credentials: creds})}, nil
}

// svcByKey - unexported method used to determine which region a secret was created in.
func (client *KMSClient) svcByKey(key string) (*kms.KMS, error) {
	if strings.HasPrefix(key, "arn:aws:kms:") {
		region := strings.Split(key, ":")[3]
		if *client.svc.Config.Region != region {
			sess, err := session.NewSession(&aws.Config{Region: aws.String(region)})
			if err != nil {
				return nil, err
			}
			return kms.New(sess), nil
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
