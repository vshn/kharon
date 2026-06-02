package emcred

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/passbolt/go-passbolt/api"
	"sigs.k8s.io/yaml"
)

const (
	defaultEndpoint = "https://cloud.passbolt.com/vshn"
	// defaultEmergencyCredentialsBucketConfigName is the name of the resource in passbolt that contains the bucket configuration.
	// Yes there is a typo in the name 🙃
	defaultEmergencyCredentialsBucketConfigName = "emergency-cedentials-buckets"

	passboltMFACookieName = "passbolt_mfa"
)

var userAgent = sync.OnceValue(func() string {
	version := "unknown"
	if i, ok := debug.ReadBuildInfo(); ok {
		version = i.Main.Version
	}
	return fmt.Sprintf("kharon/%s", version)
})

func GetCredentials(ctx context.Context, clusterID string, keyCallback, passphraseCallback, totpCallback func() (string, error)) ([]string, error) {
	var keyStored bool
	passboltKey, err := ReadPassboltKey()
	if err == nil {
		keyStored = true
	} else {
		slog.Debug("Failed to read passbolt key from config, will try legacy config and then prompt user", "error", err)
	}

	if passboltKey == "" {
		c, err := readLegacyConfig()
		if err != nil {
			slog.Debug("Failed to retrieve legacy configuration", "error", err)
		}
		passboltKey = c.PassboltKey
	}

	if passboltKey == "" {
		key, err := keyCallback()
		if err != nil {
			return nil, fmt.Errorf("failed to read passbolt private key: %w", err)
		}
		passboltKey = key
	}
	if passboltKey == "" {
		return nil, fmt.Errorf("passbolt private key is required")
	}
	if !keyStored {
		if err := WritePassboltKey(passboltKey); err != nil {
			slog.Error("Failed to store passbolt key in config for future use", "error", err)
		}
	}

	passphrase, err := passphraseCallback()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}

	client, err := api.NewClient(nil, userAgent(), defaultEndpoint, passboltKey, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to create Passbolt client: %w", err)
	}
	client.MFACallback = mfaCallback(totpCallback)

	if err := client.Login(ctx); err != nil {
		return nil, fmt.Errorf("error logging into passbolt: %w", err)
	}

	buckets, err := findBucketConfig(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to find bucket config: %w", err)
	}

	var tokens []string
	for _, bucket := range buckets {
		decrypted, err := downloadAndDecrypt(ctx, client, bucket, clusterID)
		if err != nil {
			slog.Error("failed to download and decrypt token from bucket, trying next bucket if available", "bucket", bucket.Bucket, "error", err)
			continue
		}
		tokens = append(tokens, decrypted)
	}

	return tokens, nil
}

func downloadAndDecrypt(ctx context.Context, client *api.Client, bucket bucket, clusterID string) (string, error) {
	region := bucket.Region
	if region == "" {
		region = "us-east-1"
	}
	clientV2 := s3.NewFromConfig(aws.Config{
		Credentials: credentials.NewStaticCredentialsProvider(bucket.AccessKeyId, bucket.SecretAccessKey, ""),
		Region:      region,
	}, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = new(fmt.Sprintf("https://%s", bucket.Endpoint))
	})

	obj, err := clientV2.GetObject(ctx, &s3.GetObjectInput{
		Bucket: new(bucket.Bucket),
		Key:    new(fmt.Sprintf("em-%s", fmt.Sprintf("%x", sha256.Sum256([]byte(clusterID))))),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, obj.Body)
		_ = obj.Body.Close()
	}()

	var et encryptedToken
	if err := json.NewDecoder(obj.Body).Decode(&et); err != nil {
		return "", fmt.Errorf("failed to decode encrypted token: %w", err)
	}

	var decrypted string
	for _, s := range et.Secrets {
		d, err := client.DecryptMessage(s.Data)
		if err == nil {
			decrypted = d
			break
		}
	}
	if decrypted == "" {
		return "", fmt.Errorf("failed to decrypt any of the secrets for cluster %s", clusterID)
	}
	return decrypted, nil
}

type bucketConfig struct {
	Buckets []bucket `yaml:"buckets"`
}

type bucket struct {
	// Endpoint is the S3 endpoint to use.
	Endpoint string `yaml:"endpoint"`
	// Bucket is the S3 bucket to use.
	Bucket string `yaml:"bucket"`

	// AccessKeyId and SecretAccessKey are the S3 credentials to use.
	AccessKeyId string `yaml:"accessKeyId"`
	// SecretAccessKey is the S3 secret access key to use.
	SecretAccessKey string `yaml:"secretAccessKey"`

	// Region is the AWS region to use.
	Region string `yaml:"region,omitempty"`
}

func findBucketConfig(ctx context.Context, c *api.Client) ([]bucket, error) {
	res, err := c.GetResources(ctx, &api.GetResourcesOptions{})
	if err != nil {
		return nil, fmt.Errorf("error retrieving resources from passbolt: %w", err)
	}

	var resource api.Resource
	for _, r := range res {
		if r.Name == defaultEmergencyCredentialsBucketConfigName {
			resource = r
			break
		}
	}
	if resource.ID == "" {
		return nil, fmt.Errorf("could not find resource %q", defaultEmergencyCredentialsBucketConfigName)
	}
	secret, err := c.GetSecret(ctx, resource.ID)
	if err != nil {
		return nil, fmt.Errorf("error retrieving bucket secret from passbolt: %w", err)
	}

	conf, err := c.DecryptMessage(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("error decrypting bucket secret in passbolt: %w", err)
	}

	var pbsc api.SecretDataTypePasswordAndDescription
	if err := json.Unmarshal([]byte(conf), &pbsc); err != nil {
		return nil, fmt.Errorf("error parsing the decrypted passbolt secret: %w", err)
	}

	var bc bucketConfig
	if err := yaml.Unmarshal([]byte(pbsc.Password), &bc); err != nil {
		return nil, fmt.Errorf("error parsing bucket configuration from passbolt secrets password field: %w", err)
	}

	return bc.Buckets, nil
}

// mfaCallback is a callback function for the passbolt client to handle MFA challenges.
// It will prompt the user for a TOTP token if needed.
// It will return the MFA cookie if successful.
// Currently only TOTP is supported, Passbolt does not support other MFA methods as of 05.04.2024.
func mfaCallback(callback func() (string, error)) func(ctx context.Context, c *api.Client, res *api.APIResponse) (http.Cookie, error) {
	return func(ctx context.Context, c *api.Client, res *api.APIResponse) (http.Cookie, error) {
		var challenge api.MFAChallenge
		if err := json.Unmarshal(res.Body, &challenge); err != nil {
			return http.Cookie{}, fmt.Errorf("error parsing MFA Challenge: %w", err)
		}
		if challenge.Provider.TOTP == "" {
			return http.Cookie{}, fmt.Errorf("server provided no TOTP provider, only TOTP is supported currently")
		}

		code, err := callback()
		if err != nil {
			return http.Cookie{}, fmt.Errorf("failed to read TOTP token: %w", err)
		}
		if code == "" {
			return http.Cookie{}, fmt.Errorf("TOTP token is required")
		}

		raw, apiRes, err := c.DoCustomRequestAndReturnRawResponseV5(ctx, "POST", "mfa/verify/totp.json", api.MFAChallengeResponse{
			TOTP: code,
		}, nil)
		if err != nil {
			return http.Cookie{}, fmt.Errorf("error verifying MFA challenge: %w (api response: {%+v, %s}, code: %d)", err, apiRes.Header, apiRes.Body, raw.StatusCode)
		}
		// MFA worked so lets find the cookie and return it
		cookieNames := make([]string, 0, len(raw.Cookies()))
		for _, cookie := range raw.Cookies() {
			cookieNames = append(cookieNames, cookie.Name)
			if cookie.Name == passboltMFACookieName {
				return *cookie, nil
			}
		}
		return http.Cookie{}, fmt.Errorf("unable to find MFA cookie %q, cookies found: %v", passboltMFACookieName, cookieNames)
	}
}

// encryptedToken is the JSON structure of an encrypted token.
type encryptedToken struct {
	Secrets []encryptedTokenSecret `json:"secrets"`
}

// encryptedTokenSecret is the JSON structure of an encrypted token secret.
type encryptedTokenSecret struct {
	Data string `json:"data"`
}
