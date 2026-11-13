package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGCSClientOmitsMutableEncodingFromSignatureOnly(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint   string
		unsignedEncoding bool
	}{
		{"gcs", "https://storage.googleapis.com", true},
		{"gcs-bucket", "https://bucket.storage.googleapis.com", true},
		{"aws", "https://s3.us-east-2.amazonaws.com", false},
		{"other-compatible", "https://objects.example.com", false},
		{"lookalike", "https://storage.googleapis.com.example.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				called = true
				// Assert only the header's inclusion, never log authorization/signing material.
				authorization := request.Header.Get("Authorization")
				if strings.Contains(authorization, "accept-encoding") == tc.unsignedEncoding {
					t.Error("unexpected Accept-Encoding signing policy")
				}
				if request.Header.Get("Accept-Encoding") != "identity" {
					t.Error("transport encoding changed; object bytes must remain untouched")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": {"10"}},
					Body: io.NopCloser(strings.NewReader("cache-body")), ContentLength: 10}, nil
			})
			client := s3.New(s3.Options{
				Region: "auto", BaseEndpoint: aws.String(tc.endpoint), UsePathStyle: true,
				Credentials: credentials.NewStaticCredentialsProvider("SYNTHETIC", "synthetic-secret", ""),
				HTTPClient:  &http.Client{Transport: transport}, RetryMaxAttempts: 1,
				RequestChecksumCalculation: aws.RequestChecksumCalculationWhenSupported,
			}, func(options *s3.Options) { configureGCSSigning(tc.endpoint, options) })
			expectedChecksum := aws.RequestChecksumCalculationWhenSupported
			if tc.unsignedEncoding {
				expectedChecksum = aws.RequestChecksumCalculationWhenRequired
			}
			if client.Options().RequestChecksumCalculation != expectedChecksum {
				t.Error("unexpected optional request checksum policy")
			}
			response, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String("test-bucket"), Key: aws.String("key")})
			if err != nil {
				t.Fatal("GetObject failed against synthetic transport")
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "cache-body" || !called {
				t.Error("object transport did not preserve data")
			}
		})
	}
}

type failingSigner struct {
	failure error
	called  bool
}

func (s *failingSigner) SignHTTP(_ context.Context, _ aws.Credentials, r *http.Request, _, _, _ string, _ time.Time, _ ...func(*v4.SignerOptions)) error {
	s.called = true
	if r.Header.Get("Accept-Encoding") != "" {
		return errors.New("header was not omitted before signing")
	}
	return s.failure
}

func TestGCSSignerRestoresEncodingEvenWhenSigningFails(t *testing.T) {
	failure := errors.New("synthetic signer failure")
	base := &failingSigner{failure: failure}
	request, _ := http.NewRequest("GET", "https://storage.googleapis.com/bucket/key", nil)
	request.Header["Accept-Encoding"] = []string{"identity", "custom"}
	err := (&gcsHTTPV4Signer{base: base}).SignHTTP(context.Background(), aws.Credentials{}, request, "", "s3", "auto", time.Now())
	if !errors.Is(err, failure) || !base.called {
		t.Fatal("signing error was not preserved")
	}
	if got := request.Header.Values("Accept-Encoding"); len(got) != 2 || got[0] != "identity" || got[1] != "custom" {
		t.Error("encoding header was not restored")
	}
}
