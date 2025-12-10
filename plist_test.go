package main

import (
	"crypto/x509"
	"testing"

	opb "github.com/appsworld/katalinaware/protos"
	"github.com/beevik/etree"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestParsePlist(t *testing.T) {
	tests := []struct {
		desc    string
		plist   string
		want    map[string]interface{}
		wantErr bool
	}{
		{
			desc:  "Parse a valid plist",
			plist: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n  <dict>\n    <key>com.apple.security.cs.allow-jit</key>\n    <true/>\n    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>\n    <true/>\n  </dict>\n</plist>",
			want: map[string]interface{}{
				"com.apple.security.cs.allow-jit":                        interface{}(true),
				"com.apple.security.cs.allow-unsigned-executable-memory": interface{}(true),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			doc := etree.NewDocument()
			err := doc.ReadFromString(tt.plist)
			if err != nil {
				t.Fatalf("error: could not create tree from xml object: %v", err)
			}
			root := doc.SelectElement("plist")
			child := root.SelectElement("dict")
			got, err := parsePlistTree(child)
			if err != nil && !tt.wantErr {
				t.Errorf("unexpected error: could not parse tree : %v", err)
			}
			if eq := cmp.Equal(tt.want, got, cmpopts.EquateEmpty()); !eq {
				t.Errorf("ParsePlist(child): returned %v, expected %v", got, tt.want)
			}
		})
	}
}

func TestCheckRevocation(t *testing.T) {
	// This is a partial test since we can't fully test the OCSP functionality without mocks

	tests := []struct {
		name         string
		certificates []*x509.Certificate
		cFeat        *opb.CertFeaturesML
		certs        []*opb.Certificate
		// We can't fully verify the behavior without mocking the OCSP response
		// So we're just checking that the function doesn't panic
		expectPanic bool
	}{
		{
			name:         "Empty certificates",
			certificates: []*x509.Certificate{},
			cFeat:        &opb.CertFeaturesML{},
			certs:        []*opb.Certificate{},
			expectPanic:  false,
		},
		{
			name:         "Empty certificate list with non-empty certs array",
			certificates: []*x509.Certificate{},
			cFeat:        &opb.CertFeaturesML{},
			certs:        []*opb.Certificate{{IsCaSigned: false}},
			expectPanic:  false,
		},
		{
			name:         "Non-empty certificates with empty certs array",
			certificates: []*x509.Certificate{{}}, // Not valid but shouldn't panic
			cFeat:        &opb.CertFeaturesML{},
			certs:        []*opb.Certificate{},
			expectPanic:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.expectPanic {
					t.Errorf("checkRevocation() panic = %v, expectPanic = %v", r != nil, tt.expectPanic)
				}
			}()

			checkRevocation(tt.certificates, tt.cFeat, tt.certs)
		})
	}
}

func TestGetCodeSigning_Integration(t *testing.T) {
	// Setup
	emptyCertFeatures := emptyCeryFeaturesML
	var emptyCertificates []*opb.Certificate // Using nil slice instead of empty slice

	tests := []struct {
		name     string
		reader   *MachoReader
		wantFeat *opb.CertFeaturesML
		wantCert []*opb.Certificate
	}{
		{
			name:     "Nil reader",
			reader:   nil,
			wantFeat: emptyCertFeatures,
			wantCert: emptyCertificates, // This is nil
		},
		{
			name: "Reader with nil macho reader",
			reader: &MachoReader{
				MachoReader: nil,
			},
			wantFeat: emptyCertFeatures,
			wantCert: emptyCertificates, // This is nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use defer/recover to catch panics
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("getCodeSigning() panicked: %v", r)
				}
			}()

			gotFeat, gotCert := getCodeSigning(tt.reader)

			// Use cmpopts.IgnoreUnexported to ignore unexported fields in protobuf types
			opts := cmp.Options{
				cmpopts.IgnoreUnexported(opb.CertFeaturesML{}),
				cmpopts.IgnoreUnexported(opb.Certificate{}),
				cmpopts.IgnoreUnexported(opb.CertIssuerSubj{}),
				// Add any other protobuf types you need to compare

				// Add an option to treat nil slices and empty slices as equal
				cmpopts.EquateEmpty(),
			}

			if !cmp.Equal(gotFeat, tt.wantFeat, opts) {
				t.Errorf("getCodeSigning() returned unexpected CertFeaturesML\ngot:  %v\nwant: %v\ndiff: %v",
					gotFeat, tt.wantFeat, cmp.Diff(gotFeat, tt.wantFeat, opts))
			}

			if !cmp.Equal(gotCert, tt.wantCert, opts) {
				t.Errorf("getCodeSigning() returned unexpected Certificate slice\ngot:  %v\nwant: %v\ndiff: %v",
					gotCert, tt.wantCert, cmp.Diff(gotCert, tt.wantCert, opts))
			}
		})
	}
}
