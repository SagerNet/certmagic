// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"github.com/sagernet/certmagic/internal/testutil"
)

func TestSaveCertResource(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domain := "example.com"
	certContents := "certificate"
	keyContents := "private key"

	cert := CertificateResource{
		SANs:           []string{domain},
		PrivateKeyPEM:  []byte(keyContents),
		CertificatePEM: []byte(certContents),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	siteData, err := testConfig.loadCertResource(ctx, am, domain)
	if err != nil {
		t.Fatalf("Expected no error reading site, got: %v", err)
	}
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte("\t"), []byte(""))
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte("\n"), []byte(""))
	siteData.IssuerData = bytes.ReplaceAll(siteData.IssuerData, []byte(" "), []byte(""))
	if !reflect.DeepEqual(cert, siteData) {
		t.Errorf("Expected '%+v' to match '%+v'\n%s\n%s", cert.IssuerData, siteData.IssuerData, string(cert.IssuerData), string(siteData.IssuerData))
	}
}

type mockStorageWithLease struct {
	*FileStorage
	renewCalled  bool
	renewError   error
	lastLockKey  string
	lastDuration time.Duration
}

func (m *mockStorageWithLease) RenewLockLease(ctx context.Context, lockKey string, leaseDuration time.Duration) error {
	m.renewCalled = true
	m.lastLockKey = lockKey
	m.lastDuration = leaseDuration
	return m.renewError
}

func TestRenewLockLeaseDuration(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	mockStorage := &mockStorageWithLease{
		FileStorage: &FileStorage{Path: tmpDir},
	}

	// Test attempt 0
	cfg := &Config{Logger: defaultTestLogger}
	cfg.renewLockLease(ctx, mockStorage, "test-lock", 0)
	expected := retryIntervals[0] + DefaultACME.CertObtainTimeout
	testutil.RequireEqual(t, expected, mockStorage.lastDuration)

	// Test attempt beyond array bounds
	cfg.renewLockLease(ctx, mockStorage, "test-lock", 999)
	expected = maxRetryDuration + DefaultACME.CertObtainTimeout
	testutil.RequireEqual(t, expected, mockStorage.lastDuration)
}

// Test that lease renewal works when storage supports it
func TestRenewLockLeaseWithInterface(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	mockStorage := &mockStorageWithLease{
		FileStorage: &FileStorage{Path: tmpDir},
	}

	cfg := &Config{Logger: defaultTestLogger}
	err = cfg.renewLockLease(ctx, mockStorage, "test-lock", 0)
	testutil.RequireNoError(t, err)

	testutil.RequireEqual(t, true, mockStorage.renewCalled)
}

// Test that no error occurs when storage doesn't support lease renewal
func TestRenewLockLeaseWithoutInterface(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic-test*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)

	storage := &FileStorage{Path: tmpDir}

	cfg := &Config{Logger: defaultTestLogger}
	err = cfg.renewLockLease(ctx, storage, "test-lock", 0)
	testutil.RequireNoError(t, err)
}

func mustJSON(val any) []byte {
	result, err := json.Marshal(val)
	if err != nil {
		panic("marshaling JSON: " + err.Error())
	}
	return result
}

// Test SAN utility functions

func TestCompareSANs(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "identical lists",
			a:        []string{"example.com", "www.example.com"},
			b:        []string{"example.com", "www.example.com"},
			expected: true,
		},
		{
			name:     "same elements, different order",
			a:        []string{"www.example.com", "example.com"},
			b:        []string{"example.com", "www.example.com"},
			expected: true,
		},
		{
			name:     "case insensitive",
			a:        []string{"Example.COM", "WWW.example.com"},
			b:        []string{"example.com", "www.EXAMPLE.com"},
			expected: true,
		},
		{
			name:     "different lengths",
			a:        []string{"example.com"},
			b:        []string{"example.com", "www.example.com"},
			expected: false,
		},
		{
			name:     "different domains",
			a:        []string{"example.com", "api.example.com"},
			b:        []string{"example.com", "www.example.com"},
			expected: false,
		},
		{
			name:     "empty lists",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "one empty list",
			a:        []string{"example.com"},
			b:        []string{},
			expected: false,
		},
		{
			name:     "with whitespace",
			a:        []string{" example.com ", "www.example.com"},
			b:        []string{"example.com", " www.example.com "},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareSANs(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("compareSANs(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestValidateSANList(t *testing.T) {
	tests := []struct {
		name      string
		sans      []string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid single SAN",
			sans:      []string{"example.com"},
			expectErr: false,
		},
		{
			name:      "valid multiple SANs",
			sans:      []string{"example.com", "www.example.com", "api.example.com"},
			expectErr: false,
		},
		{
			name:      "empty list",
			sans:      []string{},
			expectErr: true,
			errMsg:    "SAN list cannot be empty",
		},
		{
			name:      "duplicate SANs",
			sans:      []string{"example.com", "example.com"},
			expectErr: true,
			errMsg:    "duplicate name",
		},
		{
			name:      "duplicate SANs case insensitive",
			sans:      []string{"example.com", "EXAMPLE.COM"},
			expectErr: true,
			errMsg:    "duplicate name",
		},
		{
			name:      "too many SANs",
			sans:      make([]string, 101),
			expectErr: true,
			errMsg:    "SAN list too large",
		},
		{
			name:      "empty name in list",
			sans:      []string{"example.com", "", "www.example.com"},
			expectErr: true,
			errMsg:    "empty name",
		},
		{
			name:      "exactly 100 SANs",
			sans:      make([]string, 100),
			expectErr: false,
		},
	}

	// Initialize the test case with 100 unique SANs
	for i := range tests[len(tests)-1].sans {
		tests[len(tests)-1].sans[i] = "domain" + string(rune('0'+i%10)) + string(rune('a'+i/10)) + ".com"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSANList(tt.sans)
			if tt.expectErr {
				if err == nil {
					t.Errorf("validateSANList() expected error containing %q, got nil", tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateSANList() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNamesKey(t *testing.T) {
	tests := []struct {
		name     string
		sans     []string
		expected string
	}{
		{
			name:     "single SAN",
			sans:     []string{"example.com"},
			expected: "example.com",
		},
		{
			name:     "multiple SANs sorted",
			sans:     []string{"example.com", "www.example.com"},
			expected: "example.com,www.example.com",
		},
		{
			name:     "multiple SANs unsorted",
			sans:     []string{"www.example.com", "api.example.com", "example.com"},
			expected: "api.example.com,example.com,www.example.com",
		},
		{
			name:     "empty list",
			sans:     []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := namesKey(tt.sans)
			if result != tt.expected {
				t.Errorf("namesKey(%v) = %q, want %q", tt.sans, result, tt.expected)
			}
		})
	}
}

func TestSaveCertResourceMultiSAN(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp_multisan"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		err := os.RemoveAll(testStorageDir)
		if err != nil {
			t.Fatalf("Could not remove temporary storage directory (%s): %v", testStorageDir, err)
		}
	}()

	domains := []string{"example.com", "www.example.com", "api.example.com"}
	certContents := "certificate"
	keyContents := "private key"

	cert := CertificateResource{
		SANs:           domains,
		PrivateKeyPEM:  []byte(keyContents),
		CertificatePEM: []byte(certContents),
		IssuerData: mustJSON(acme.Certificate{
			URL: "https://example.com/cert",
		}),
		issuerKey: am.IssuerKey(),
	}

	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Load using the multi-SAN function
	loadedCert, err := testConfig.loadCertResourceMultiSAN(ctx, am, domains)
	if err != nil {
		t.Fatalf("Expected no error reading multi-SAN cert, got: %v", err)
	}

	// Normalize JSON for comparison
	loadedCert.IssuerData = bytes.ReplaceAll(loadedCert.IssuerData, []byte("\t"), []byte(""))
	loadedCert.IssuerData = bytes.ReplaceAll(loadedCert.IssuerData, []byte("\n"), []byte(""))
	loadedCert.IssuerData = bytes.ReplaceAll(loadedCert.IssuerData, []byte(" "), []byte(""))

	if !reflect.DeepEqual(cert.SANs, loadedCert.SANs) {
		t.Errorf("Expected SANs %v to match %v", cert.SANs, loadedCert.SANs)
	}
	if !bytes.Equal(cert.CertificatePEM, loadedCert.CertificatePEM) {
		t.Errorf("Certificate PEM does not match")
	}
	if !bytes.Equal(cert.PrivateKeyPEM, loadedCert.PrivateKeyPEM) {
		t.Errorf("Private key PEM does not match")
	}
}

func TestStorageHasCertResourcesMultiSAN(t *testing.T) {
	ctx := context.Background()

	am := &ACMEIssuer{CA: "https://example.com/acme/directory"}
	testConfig := &Config{
		Issuers:   []Issuer{am},
		Storage:   &FileStorage{Path: "./_testdata_tmp_multisan_check"},
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am.config = testConfig

	testStorageDir := testConfig.Storage.(*FileStorage).Path
	defer func() {
		os.RemoveAll(testStorageDir)
	}()

	domains := []string{"example.com", "www.example.com"}

	// Should not exist initially
	exists := testConfig.storageHasCertResourcesMultiSAN(ctx, am, domains)
	if exists {
		t.Error("Expected cert to not exist, but it does")
	}

	// Save a cert
	cert := CertificateResource{
		SANs:           domains,
		PrivateKeyPEM:  []byte("key"),
		CertificatePEM: []byte("cert"),
		IssuerData:     mustJSON(acme.Certificate{URL: "https://example.com/cert"}),
		issuerKey:      am.IssuerKey(),
	}
	err := testConfig.saveCertResource(ctx, am, cert)
	if err != nil {
		t.Fatalf("Error saving cert: %v", err)
	}

	// Should exist now
	exists = testConfig.storageHasCertResourcesMultiSAN(ctx, am, domains)
	if !exists {
		t.Error("Expected cert to exist, but it doesn't")
	}

	// Check with any issuer function
	existsAny := testConfig.storageHasCertResourcesAnyIssuerMultiSAN(ctx, domains)
	if !existsAny {
		t.Error("Expected cert to exist for any issuer, but it doesn't")
	}
}
