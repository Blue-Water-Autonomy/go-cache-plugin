package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Google front ends can rewrite Accept-Encoding before verifying XML API
// signatures. Keep the SDK's identity encoding on the wire so cache bytes are
// never transparently decompressed, but omit this mutable header while signing.
// See https://github.com/aws/aws-sdk-go-v2/issues/1816.
// AWS and other endpoints retain their original signer without changes.
func configureGCSSigning(endpoint string, options *s3.Options) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" {
		return
	}
	host := parsed.Hostname()
	if host != "storage.googleapis.com" && !strings.HasSuffix(host, ".storage.googleapis.com") {
		return
	}
	// GCS does not support the SDK's optional S3 streaming checksum encoding.
	// Required checksums remain enabled; other endpoints retain their policy.
	options.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	base := options.HTTPSignerV4
	if base == nil {
		base = v4.NewSigner()
	}
	options.HTTPSignerV4 = &gcsHTTPV4Signer{base: base}
}

type gcsHTTPV4Signer struct{ base s3.HTTPSignerV4 }

func (s *gcsHTTPV4Signer) SignHTTP(ctx context.Context, credentials aws.Credentials, request *http.Request,
	payloadHash, service, region string, signingTime time.Time, options ...func(*v4.SignerOptions)) error {
	encoding, exists := request.Header["Accept-Encoding"]
	request.Header.Del("Accept-Encoding")
	defer func() {
		if exists {
			request.Header["Accept-Encoding"] = encoding
		}
	}()
	return s.base.SignHTTP(ctx, credentials, request, payloadHash, service, region, signingTime, options...)
}
