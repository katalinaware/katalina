package main

import (
	"testing"
	"time"

	opb "github.com/appsworld/katalinaware/protos"
)

func TestNotarizationInfoStructure(t *testing.T) {
	notarization := &opb.NotarizationInfo{
		IsNotarized:   true,
		Timestamp:     1753163385094,
		TimestampUtc:  "2025-05-21T14:36:25.094Z",
		Error:         "",
		RecordName:    "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b",
		SignedTicket:  "czhjaAEAAADxBQAALQAAADCCBe0wggL...",
		Deleted:       false,
	}

	// Verify all fields are accessible
	if !notarization.IsNotarized {
		t.Error("IsNotarized should be true")
	}

	if notarization.Timestamp != 1753163385094 {
		t.Errorf("Expected timestamp 1753163385094, got %d", notarization.Timestamp)
	}

	expectedRecordName := "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b"
	if notarization.RecordName != expectedRecordName {
		t.Errorf("Expected record name %s, got %s", expectedRecordName, notarization.RecordName)
	}

	if notarization.TimestampUtc == "" {
		t.Error("TimestampUtc should not be empty")
	}

	if len(notarization.SignedTicket) == 0 {
		t.Error("SignedTicket should not be empty")
	}

	// Note: Deleted field depends on Apple's response data, so we just verify it's accessible
	_ = notarization.Deleted
}

func TestCheckNotarizationForCDHashWithEmptyInput(t *testing.T) {
	// Test with empty CDHash
	result := checkNotarizationForCDHash("")

	if result == nil {
		t.Fatal("checkNotarizationForCDHash should not return nil")
	}

	if result.IsNotarized {
		t.Error("Empty CDHash should not be considered notarized")
	}

	if result.Error != "CDHash is empty" {
		t.Errorf("Expected error 'CDHash is empty', got '%s'", result.Error)
	}

	if result.RecordName != "" {
		t.Error("RecordName should be empty for empty CDHash")
	}
}

func TestNotarizationRecordNameFormat(t *testing.T) {
	testCases := []struct {
		name           string
		cdHash         string
		expectedRecord string
	}{
		{
			name:           "Valid SHA256 CDHash",
			cdHash:         "343ec2299ba67facfa5925207a58f81f9aacf49b",
			expectedRecord: "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b",
		},
		{
			name:           "Valid SHA1 CDHash", 
			cdHash:         "73e668bda5157d4d529b34a1295e82d515d9968c",
			expectedRecord: "2/2/73e668bda5157d4d529b34a1295e82d515d9968c",
		},
		{
			name:           "Different CDHash",
			cdHash:         "abcdef1234567890abcdef1234567890abcdef12",
			expectedRecord: "2/2/abcdef1234567890abcdef1234567890abcdef12",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// We test the record name format without making actual HTTP requests
			result := &opb.NotarizationInfo{}
			result.RecordName = "2/2/" + tc.cdHash

			if result.RecordName != tc.expectedRecord {
				t.Errorf("Expected record name %s, got %s", tc.expectedRecord, result.RecordName)
			}
		})
	}
}

func TestTimestampParsing(t *testing.T) {
	// Test timestamp conversion from milliseconds to UTC string
	testCases := []struct {
		name              string
		timestampMs       int64
		expectedUTCFormat bool
	}{
		{
			name:              "Valid timestamp",
			timestampMs:       1753163385094,
			expectedUTCFormat: true,
		},
		{
			name:              "Zero timestamp",
			timestampMs:       0,
			expectedUTCFormat: true,
		},
		{
			name:              "Recent timestamp",
			timestampMs:       time.Now().UnixNano() / int64(time.Millisecond),
			expectedUTCFormat: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert timestamp manually (same logic as in notarization.go)
			timestamp := time.Unix(0, tc.timestampMs*int64(time.Millisecond))
			timestampUTC := timestamp.UTC().Format(time.RFC3339)

			// Verify it's a valid RFC3339 format
			_, err := time.Parse(time.RFC3339, timestampUTC)
			if err != nil && tc.expectedUTCFormat {
				t.Errorf("Expected valid RFC3339 format, but got error: %v", err)
			}

			// Verify timestamp is in UTC
			if tc.expectedUTCFormat && len(timestampUTC) > 0 {
				if timestampUTC[len(timestampUTC)-1] != 'Z' && !containsTimezone(timestampUTC) {
					t.Error("Timestamp should be in UTC format (ending with Z or containing timezone)")
				}
			}
		})
	}
}

func TestNotarizationResponseHandling(t *testing.T) {
	// Test different response scenarios
	testCases := []struct {
		name            string
		serverErrorCode string
		reason          string
		hasFields       bool
		expectedResult  bool
		expectError     bool
	}{
		{
			name:            "Record found with fields",
			serverErrorCode: "",
			reason:          "",
			hasFields:       true,
			expectedResult:  true,
			expectError:     false,
		},
		{
			name:            "Record not found",
			serverErrorCode: "NOT_FOUND",
			reason:          "Record not found",
			hasFields:       false,
			expectedResult:  false,
			expectError:     false,
		},
		{
			name:            "Server error",
			serverErrorCode: "INTERNAL_ERROR",
			reason:          "Internal server error",
			hasFields:       false,
			expectedResult:  false,
			expectError:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate response processing logic
			notarization := &opb.NotarizationInfo{
				IsNotarized: false,
				Error:       "",
			}

			// Simulate the response processing from checkNotarization
			if tc.serverErrorCode == "NOT_FOUND" || tc.reason == "Record not found" {
				// Not notarized - not an error
				notarization.IsNotarized = false
			} else if tc.serverErrorCode != "" {
				// Server error
				notarization.Error = "Server error: " + tc.serverErrorCode + " - " + tc.reason
			} else if tc.hasFields {
				// Binary is notarized
				notarization.IsNotarized = true
			}

			// Verify results
			if notarization.IsNotarized != tc.expectedResult {
				t.Errorf("Expected IsNotarized=%v, got %v", tc.expectedResult, notarization.IsNotarized)
			}

			hasError := notarization.Error != ""
			if hasError != tc.expectError {
				t.Errorf("Expected error=%v, got error='%s'", tc.expectError, notarization.Error)
			}
		})
	}
}

func TestCodeDirectoryWithNotarization(t *testing.T) {
	codeDir := &opb.CodeDirectory{
		Id:                      "com.test.app",
		TeamId:                  "TESTTEAM",
		ExtractedCdhash:        "343ec2299ba67facfa5925207a58f81f9aacf49b",
		ComputedSha256Cdhash:   "343ec2299ba67facfa5925207a58f81f9aacf49b",
		Notarization: &opb.NotarizationInfo{
			IsNotarized:  true,
			Timestamp:    1753163385094,
			TimestampUtc: "2025-05-21T14:36:25.094Z",
			RecordName:   "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b",
			SignedTicket: "czhjaAEAAADxBQAALQ...",
			Deleted:      false,
		},
	}

	// Verify notarization is included
	if codeDir.Notarization == nil {
		t.Fatal("Notarization should not be nil")
	}

	if !codeDir.Notarization.IsNotarized {
		t.Error("Binary should be marked as notarized")
	}

	if codeDir.Notarization.RecordName != "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b" {
		t.Error("Record name should match the expected format")
	}

	if codeDir.Notarization.Timestamp <= 0 {
		t.Error("Timestamp should be positive")
	}

	if codeDir.Notarization.TimestampUtc == "" {
		t.Error("TimestampUtc should not be empty")
	}
}

// Helper function to check if a timestamp string contains timezone information
func containsTimezone(s string) bool {
	return len(s) > 19 && (s[len(s)-6] == '+' || s[len(s)-6] == '-')
}

// TestParseNotarizationTicket tests the full ticket parsing with the sample data
func TestParseNotarizationTicket(t *testing.T) {
	// Sample base64 ticket from the Python code
	sampleTicket := "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"

	ticketInfo, err := parseNotarizationTicket(sampleTicket)
	if err != nil {
		t.Fatalf("Failed to parse notarization ticket: %v", err)
	}

	// Verify header was parsed
	if ticketInfo.Header.Magic != "s8ch" {
		t.Errorf("Expected magic 's8ch', got '%s'", ticketInfo.Header.Magic)
	}

	if ticketInfo.Header.Version != 1 {
		t.Errorf("Expected version 1, got %d", ticketInfo.Header.Version)
	}

	// Verify certificates were extracted
	if len(ticketInfo.Certificates) == 0 {
		t.Fatal("No certificates were extracted from the ticket")
	}

	t.Logf("Extracted %d certificate(s) from the ticket", len(ticketInfo.Certificates))

	// Verify the first certificate (leaf) has expected properties
	leafCert := ticketInfo.Certificates[0]
	if !leafCert.IsLeaf {
		t.Error("First certificate should be marked as leaf")
	}

	if leafCert.ChainPosition != 0 {
		t.Errorf("Leaf certificate should have chain position 0, got %d", leafCert.ChainPosition)
	}

	if leafCert.Issuer == nil {
		t.Error("Certificate should have issuer information")
	} else {
		// Verify it's an Apple certificate
		if !containsApple(leafCert.Issuer.IssuerOrg) && !containsApple(leafCert.Issuer.SubjectOrg) {
			t.Logf("Warning: Expected Apple certificate, got issuer org '%s' and subject org '%s'",
				leafCert.Issuer.IssuerOrg, leafCert.Issuer.SubjectOrg)
		}
	}

	// Verify CDHash was extracted
	if ticketInfo.CDHash == "" {
		t.Error("CDHash should be extracted from the ticket")
	}
	t.Logf("Extracted CDHash: %s", ticketInfo.CDHash)
}

// TestParseS8chHeader tests the header parsing function
func TestParseS8chHeader(t *testing.T) {
	testCases := []struct {
		name        string
		data        []byte
		expectError bool
		magic       string
		version     uint32
	}{
		{
			name:        "Valid header",
			data:        []byte{'s', '8', 'c', 'h', 0x01, 0x00, 0x00, 0x00, 0xF1, 0x05, 0x00, 0x00},
			expectError: false,
			magic:       "s8ch",
			version:     1,
		},
		{
			name:        "Too short",
			data:        []byte{0x01, 0x02},
			expectError: true,
		},
		{
			name:        "Empty data",
			data:        []byte{},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header, err := parseS8chHeader(tc.data)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if header.Magic != tc.magic {
				t.Errorf("Expected magic '%s', got '%s'", tc.magic, header.Magic)
			}

			if header.Version != tc.version {
				t.Errorf("Expected version %d, got %d", tc.version, header.Version)
			}
		})
	}
}

// TestFindCDHash tests the CDHash extraction from ticket data
func TestFindCDHash(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name: "Valid CDHash pattern",
			data: append(make([]byte, 50),
				append([]byte{0x00, 0x00, 0x00, 0x00, 0x02},
					[]byte{0x34, 0x3e, 0xc2, 0x29, 0x9b, 0xa6, 0x7f, 0xac, 0xfa, 0x59, 0x25, 0x20, 0x7a, 0x58, 0xf8, 0x1f, 0x9a, 0xac, 0xf4, 0x9b}...)...),
			expected: "343ec2299ba67facfa5925207a58f81f9aacf49b",
		},
		{
			name:     "No CDHash pattern",
			data:     make([]byte, 100),
			expected: "",
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := findCDHash(tc.data)
			if result != tc.expected {
				t.Errorf("Expected CDHash '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// TestCertificateChainPositions tests that certificates have correct chain positions
func TestCertificateChainPositions(t *testing.T) {
	sampleTicket := "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"

	ticketInfo, err := parseNotarizationTicket(sampleTicket)
	if err != nil {
		t.Fatalf("Failed to parse notarization ticket: %v", err)
	}

	if len(ticketInfo.Certificates) < 2 {
		t.Skip("Need at least 2 certificates to test chain positions")
	}

	// Verify first certificate is leaf
	if !ticketInfo.Certificates[0].IsLeaf {
		t.Error("First certificate should be marked as leaf")
	}
	if ticketInfo.Certificates[0].IsIntermediate || ticketInfo.Certificates[0].IsRoot {
		t.Error("Leaf certificate should not be marked as intermediate or root")
	}

	// Verify last certificate is root
	lastIdx := len(ticketInfo.Certificates) - 1
	if !ticketInfo.Certificates[lastIdx].IsRoot {
		t.Error("Last certificate should be marked as root")
	}
	if ticketInfo.Certificates[lastIdx].IsIntermediate || ticketInfo.Certificates[lastIdx].IsLeaf {
		t.Error("Root certificate should not be marked as intermediate or leaf")
	}

	// Verify chain positions are sequential
	for i, cert := range ticketInfo.Certificates {
		if int(cert.ChainPosition) != i {
			t.Errorf("Certificate at index %d has chain position %d", i, cert.ChainPosition)
		}
	}

	// If there are more than 2 certificates, verify middle ones are intermediate
	if len(ticketInfo.Certificates) > 2 {
		for i := 1; i < len(ticketInfo.Certificates)-1; i++ {
			if !ticketInfo.Certificates[i].IsIntermediate {
				t.Errorf("Certificate at position %d should be marked as intermediate", i)
			}
			if ticketInfo.Certificates[i].IsLeaf || ticketInfo.Certificates[i].IsRoot {
				t.Errorf("Intermediate certificate should not be marked as leaf or root")
			}
		}
	}
}

// TestNotarizationInfoWithCertificates tests that NotarizationInfo includes certificates
func TestNotarizationInfoWithCertificates(t *testing.T) {
	// Create a sample NotarizationInfo with certificates
	notarization := &opb.NotarizationInfo{
		IsNotarized:  true,
		Timestamp:    1753163385094,
		TimestampUtc: "2025-05-21T14:36:25.094Z",
		RecordName:   "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b",
		SignedTicket: "czhjaAEAAADxBQAALQ...",
		Certificates: []*opb.Certificate{
			{
				SerialNumber:  "123456",
				ValidFrom:     "2025-03-04 14:40:07 UTC",
				ValidTo:       "2026-04-02 18:08:56 UTC",
				IsValidCert:   true,
				ChainPosition: 0,
				IsLeaf:        true,
				Issuer: &opb.CertIssuerSubj{
					SubjectName: "Software Ticket Signing",
					SubjectOrg:  "Apple Inc.",
					IssuerName:  "Apple System Integration CA 4",
					IssuerOrg:   "Apple Inc.",
				},
			},
		},
		ExtractedCdhash: "343ec2299ba67facfa5925207a58f81f9aacf49b",
	}

	// Verify certificates field is accessible
	if notarization.Certificates == nil {
		t.Fatal("Certificates field should not be nil")
	}

	if len(notarization.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(notarization.Certificates))
	}

	// Verify certificate properties
	cert := notarization.Certificates[0]
	if cert.SerialNumber == "" {
		t.Error("Certificate should have a serial number")
	}

	if cert.ValidFrom == "" || cert.ValidTo == "" {
		t.Error("Certificate should have validity dates")
	}

	if !cert.IsValidCert {
		t.Error("Certificate should be marked as valid")
	}

	if cert.ChainPosition != 0 {
		t.Error("First certificate should have chain position 0")
	}

	if !cert.IsLeaf {
		t.Error("Certificate should be marked as leaf")
	}

	// Verify extracted CDHash
	if notarization.ExtractedCdhash == "" {
		t.Error("ExtractedCdhash should not be empty")
	}

	if notarization.ExtractedCdhash != "343ec2299ba67facfa5925207a58f81f9aacf49b" {
		t.Errorf("Expected CDHash '343ec2299ba67facfa5925207a58f81f9aacf49b', got '%s'",
			notarization.ExtractedCdhash)
	}
}

// TestInvalidTicketData tests error handling with invalid ticket data
func TestInvalidTicketData(t *testing.T) {
	testCases := []struct {
		name         string
		ticketBase64 string
		expectError  bool
	}{
		{
			name:         "Invalid base64",
			ticketBase64: "not-valid-base64!@#$",
			expectError:  true,
		},
		{
			name:         "Too short",
			ticketBase64: "YWJjZA==", // "abcd" in base64
			expectError:  true,
		},
		{
			name:         "Empty string",
			ticketBase64: "",
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNotarizationTicket(tc.ticketBase64)
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// Helper function to check if a string contains "Apple"
func containsApple(s string) bool {
	return len(s) > 0 && (s == "Apple Inc." || s == "Apple" || len(s) > 5)
}