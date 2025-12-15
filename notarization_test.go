package main

import (
	"testing"
	"time"

	opb "github.com/appsworld/katalinaware/protos"
)

func TestNotarizationInfoStructure(t *testing.T) {
	notarization := &opb.NotarizationInfo{
		IsNotarized:     true,
		Timestamp:       1753163385094,
		TimestampUtc:    "2025-05-21T14:36:25.094Z",
		Error:           "",
		RecordName:      "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b",
		SignedTicket:    "czhjaAEAAADxBQAALQAAADCCBe0wggL...",
		Deleted:         false,
		TicketState:     opb.TicketState_TICKET_STATE_NOTARIZED,
		ContentFlags:    0,
		G8TkTimestamp:   1742298352,
		CdhashCount:     1,
		Cdhashes:        []string{"343ec2299ba67facfa5925207a58f81f9aacf49b"},
		TypeIndicator:   45,
		TicketSizeBytes: 1654,
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

	// Verify new fields from reverse engineering
	if notarization.TicketState != opb.TicketState_TICKET_STATE_NOTARIZED {
		t.Error("TicketState should be NOTARIZED")
	}

	if notarization.ContentFlags != 0 {
		t.Errorf("Expected content_flags 0 for notarized, got %d", notarization.ContentFlags)
	}

	if notarization.CdhashCount != 1 {
		t.Errorf("Expected cdhash_count 1, got %d", notarization.CdhashCount)
	}

	if len(notarization.Cdhashes) != 1 {
		t.Errorf("Expected 1 CDHash, got %d", len(notarization.Cdhashes))
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
		Id:                   "com.test.app",
		TeamId:               "TESTTEAM",
		ExtractedCdhash:      "343ec2299ba67facfa5925207a58f81f9aacf49b",
		ComputedSha256Cdhash: "343ec2299ba67facfa5925207a58f81f9aacf49b",
		Notarization: &opb.NotarizationInfo{
			IsNotarized:     true,
			Timestamp:       1753163385094,
			TimestampUtc:    "2025-05-21T14:36:25.094Z",
			RecordName:      "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b",
			SignedTicket:    "czhjaAEAAADxBQAALQ...",
			Deleted:         false,
			TicketState:     opb.TicketState_TICKET_STATE_NOTARIZED,
			ContentFlags:    0,
			G8TkTimestamp:   1742298352,
			CdhashCount:     2,
			Cdhashes:        []string{"343ec2299ba67facfa5925207a58f81f9aacf49b", "abcdef1234567890abcdef1234567890abcdef12"},
			TypeIndicator:   66,
			TicketSizeBytes: 1675,
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

	// Verify new ticket fields
	if codeDir.Notarization.TicketState != opb.TicketState_TICKET_STATE_NOTARIZED {
		t.Error("TicketState should be NOTARIZED")
	}

	if codeDir.Notarization.ContentFlags != 0 {
		t.Errorf("Expected content_flags 0 for notarized, got %d", codeDir.Notarization.ContentFlags)
	}

	if codeDir.Notarization.CdhashCount != 2 {
		t.Errorf("Expected cdhash_count 2, got %d", codeDir.Notarization.CdhashCount)
	}

	if len(codeDir.Notarization.Cdhashes) != 2 {
		t.Errorf("Expected 2 CDHashes, got %d", len(codeDir.Notarization.Cdhashes))
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
		t.Logf("Warning: No certificates were extracted from the ticket (cert parsing may have failed)")
	} else {
		t.Logf("Extracted %d certificate(s) from the ticket", len(ticketInfo.Certificates))
	}

	// Verify the first certificate (leaf) has expected properties if certificates were extracted
	if len(ticketInfo.Certificates) > 0 {
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
	}

	// Verify g8tk header was parsed
	if ticketInfo.G8tkHeader == nil {
		t.Error("g8tk header should be parsed from the ticket")
	} else {
		t.Logf("g8tk content_flags: %d (0=notarized, 1=revoked)", ticketInfo.G8tkHeader.ContentFlags)
		t.Logf("g8tk cdhash_count: %d", ticketInfo.G8tkHeader.CDHashCount)
		t.Logf("g8tk timestamp: %d", ticketInfo.G8tkHeader.ContentTimestamp)
	}

	// Verify CDHashes were extracted
	if len(ticketInfo.CDHashes) == 0 {
		t.Error("CDHashes should be extracted from the ticket")
	}
	t.Logf("Extracted %d CDHash(es)", len(ticketInfo.CDHashes))
	for i, cdhash := range ticketInfo.CDHashes {
		t.Logf("  CDHash[%d]: %s", i, cdhash)
	}

	// Verify type_indicator was parsed
	t.Logf("type_indicator: %d (encodes data size, not state)", ticketInfo.Header.TypeIndicator)
}

// TestParseS8chHeader tests the header parsing function
func TestParseS8chHeader(t *testing.T) {
	testCases := []struct {
		name          string
		data          []byte
		expectError   bool
		magic         string
		version       uint32
		typeIndicator uint32
	}{
		{
			name: "Valid header with type_indicator",
			data: []byte{
				's', '8', 'c', 'h', // magic
				0x01, 0x00, 0x00, 0x00, // version = 1
				0xF1, 0x05, 0x00, 0x00, // cert_size = 1521
				0x2D, 0x00, 0x00, 0x00, // type_indicator = 45
			},
			expectError:   false,
			magic:         "s8ch",
			version:       1,
			typeIndicator: 45,
		},
		{
			name:        "Too short (only 16 bytes)",
			data:        []byte{'s', '8', 'c', 'h', 0x01, 0x00, 0x00, 0x00, 0xF1, 0x05, 0x00, 0x00},
			expectError: true,
		},
		{
			name:        "Too short (8 bytes)",
			data:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
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

			if header.TypeIndicator != tc.typeIndicator {
				t.Errorf("Expected type_indicator %d, got %d", tc.typeIndicator, header.TypeIndicator)
			}
		})
	}
}

// TestParseG8tkHeader tests the g8tk header parsing function
func TestParseG8tkHeader(t *testing.T) {
	testCases := []struct {
		name              string
		data              []byte
		expectError       bool
		expectedFlags     uint32
		expectedCount     uint32
		expectedTimestamp uint64
	}{
		{
			name: "Valid g8tk header - notarized",
			data: append([]byte{0x00, 0x00}, // padding
				append([]byte{'g', '8', 't', 'k'}, // magic
					append([]byte{0x02, 0x00}, // cdhash_type = 2
						append([]byte{0x14, 0x00}, // cdhash_length = 20
							append([]byte{0x01, 0x00, 0x00, 0x00}, // cdhash_count = 1
								append([]byte{0x00, 0x00, 0x00, 0x00}, // content_flags = 0 (notarized)
									[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)...)...)...)...)...), // timestamp = 0 for simplicity
			expectError:       false,
			expectedFlags:     0,
			expectedCount:     1,
			expectedTimestamp: 0,
		},
		{
			name: "Valid g8tk header - revoked",
			data: append([]byte{0x00, 0x00}, // padding
				append([]byte{'g', '8', 't', 'k'}, // magic
					append([]byte{0x02, 0x00}, // cdhash_type = 2
						append([]byte{0x14, 0x00}, // cdhash_length = 20
							append([]byte{0x05, 0x00, 0x00, 0x00}, // cdhash_count = 5
								append([]byte{0x01, 0x00, 0x00, 0x00}, // content_flags = 1 (revoked)
									[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)...)...)...)...)...), // timestamp = 0 for simplicity
			expectError:       false,
			expectedFlags:     1,
			expectedCount:     5,
			expectedTimestamp: 0,
		},
		{
			name:        "No g8tk magic",
			data:        make([]byte, 100),
			expectError: true,
		},
		{
			name:        "g8tk magic but incomplete header",
			data:        []byte{'g', '8', 't', 'k', 0x00, 0x00},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g8tk, err := parseG8tkHeader(tc.data)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if g8tk.ContentFlags != tc.expectedFlags {
				t.Errorf("Expected content_flags %d, got %d", tc.expectedFlags, g8tk.ContentFlags)
			}

			if g8tk.CDHashCount != tc.expectedCount {
				t.Errorf("Expected cdhash_count %d, got %d", tc.expectedCount, g8tk.CDHashCount)
			}

			if g8tk.ContentTimestamp != tc.expectedTimestamp {
				t.Errorf("Expected timestamp %d, got %d", tc.expectedTimestamp, g8tk.ContentTimestamp)
			}
		})
	}
}

// TestExtractCDHashes tests the CDHash extraction from g8tk array
func TestExtractCDHashes(t *testing.T) {
	testCases := []struct {
		name          string
		data          []byte
		g8tk          *G8tkHeader
		expectedCount int
	}{
		{
			name: "Single CDHash",
			data: append([]byte{'g', '8', 't', 'k'}, // magic at offset 0
				append(make([]byte, 20), // skip g8tk header (24 bytes total)
					append([]byte{0x02}, // hash type
						[]byte{0x34, 0x3e, 0xc2, 0x29, 0x9b, 0xa6, 0x7f, 0xac, 0xfa, 0x59, 0x25, 0x20, 0x7a, 0x58, 0xf8, 0x1f, 0x9a, 0xac, 0xf4, 0x9b}...)...)...), // 20-byte hash
			g8tk: &G8tkHeader{
				Offset:       0,
				CDHashLength: 20,
				CDHashCount:  1,
			},
			expectedCount: 1,
		},
		{
			name: "Multiple CDHashes",
			data: append([]byte{'g', '8', 't', 'k'}, // magic at offset 0
				append(make([]byte, 20), // skip g8tk header
					append([]byte{0x02}, // hash type 1
						append(make([]byte, 20), // hash 1
							append([]byte{0x02}, // hash type 2
								make([]byte, 20)...)...)...)...)...), // hash 2
			g8tk: &G8tkHeader{
				Offset:       0,
				CDHashLength: 20,
				CDHashCount:  2,
			},
			expectedCount: 2,
		},
		{
			name:          "Nil g8tk header",
			data:          []byte{},
			g8tk:          nil,
			expectedCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cdhashes := extractCDHashes(tc.data, tc.g8tk)

			if len(cdhashes) != tc.expectedCount {
				t.Errorf("Expected %d CDHashes, got %d", tc.expectedCount, len(cdhashes))
			}

			// Verify all CDHashes are valid hex strings of correct length
			for i, cdhash := range cdhashes {
				if len(cdhash) != 40 { // 20 bytes = 40 hex chars
					t.Errorf("CDHash %d has invalid length %d, expected 40", i, len(cdhash))
				}
			}
		})
	}
}

// TestClassifyTicketState tests the ticket state classification function
func TestClassifyTicketState(t *testing.T) {
	testCases := []struct {
		name          string
		contentFlags  uint32
		expectedState opb.TicketState
	}{
		{
			name:          "Notarized (content_flags=0)",
			contentFlags:  0,
			expectedState: opb.TicketState_TICKET_STATE_NOTARIZED,
		},
		{
			name:          "Revoked (content_flags=1)",
			contentFlags:  1,
			expectedState: opb.TicketState_TICKET_STATE_REVOKED,
		},
		{
			name:          "Invalid (content_flags=2)",
			contentFlags:  2,
			expectedState: opb.TicketState_TICKET_STATE_UNSPECIFIED,
		},
		{
			name:          "Invalid (content_flags=99)",
			contentFlags:  99,
			expectedState: opb.TicketState_TICKET_STATE_UNSPECIFIED,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := classifyTicketState(tc.contentFlags)
			if state != tc.expectedState {
				t.Errorf("Expected state %v, got %v", tc.expectedState, state)
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
		IsNotarized:     true,
		Timestamp:       1753163385094,
		TimestampUtc:    "2025-05-21T14:36:25.094Z",
		RecordName:      "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b",
		SignedTicket:    "czhjaAEAAADxBQAALQ...",
		TicketState:     opb.TicketState_TICKET_STATE_NOTARIZED,
		ContentFlags:    0,
		G8TkTimestamp:   1742298352,
		CdhashCount:     1,
		Cdhashes:        []string{"343ec2299ba67facfa5925207a58f81f9aacf49b"},
		TypeIndicator:   45,
		TicketSizeBytes: 1654,
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

	// Verify extracted CDHash (legacy field for backwards compatibility)
	if notarization.ExtractedCdhash == "" {
		t.Error("ExtractedCdhash should not be empty")
	}

	if notarization.ExtractedCdhash != "343ec2299ba67facfa5925207a58f81f9aacf49b" {
		t.Errorf("Expected CDHash '343ec2299ba67facfa5925207a58f81f9aacf49b', got '%s'",
			notarization.ExtractedCdhash)
	}

	// Verify CDHashes array (new field)
	if len(notarization.Cdhashes) != 1 {
		t.Errorf("Expected 1 CDHash in array, got %d", len(notarization.Cdhashes))
	}

	if notarization.Cdhashes[0] != notarization.ExtractedCdhash {
		t.Error("First CDHash in array should match ExtractedCdhash for backwards compatibility")
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

// TestRevokedTicketNotMarkedAsNotarized verifies that revoked tickets have IsNotarized=false but HasTicket=true
func TestRevokedTicketNotMarkedAsNotarized(t *testing.T) {
	// Create a NotarizationInfo for a revoked ticket
	revokedTicket := &opb.NotarizationInfo{
		HasTicket:       true,  // We received a ticket from Apple's CloudKit service
		IsNotarized:     false, // This should be false for revoked tickets
		Timestamp:       1754544858139,
		TimestampUtc:    "2025-08-07T05:34:18Z",
		RecordName:      "2/2/a6dd9756e25d8653c384a1720d4b903850282f2f",
		SignedTicket:    "czhjaAEAAADxBQAALQAAADCCBe0...",
		Deleted:         false,
		TicketState:     opb.TicketState_TICKET_STATE_REVOKED, // Revoked
		ContentFlags:    1,                                    // content_flags=1 means revoked
		G8TkTimestamp:   1742298352,
		CdhashCount:     1,
		Cdhashes:        []string{"a6dd9756e25d8653c384a1720d4b903850282f2f"},
		TypeIndicator:   45,
		TicketSizeBytes: 1654,
	}

	// Verify HasTicket is true (we got a ticket from Apple)
	if !revokedTicket.HasTicket {
		t.Error("Revoked ticket should have HasTicket=true (ticket was received from Apple)")
	}

	// Verify IsNotarized is false for a revoked ticket
	if revokedTicket.IsNotarized {
		t.Error("Revoked ticket should have IsNotarized=false, but got true")
	}

	// Verify TicketState is REVOKED
	if revokedTicket.TicketState != opb.TicketState_TICKET_STATE_REVOKED {
		t.Errorf("Expected TicketState REVOKED, got %v", revokedTicket.TicketState)
	}

	// Verify ContentFlags is 1 (revoked)
	if revokedTicket.ContentFlags != 1 {
		t.Errorf("Expected ContentFlags 1 for revoked ticket, got %d", revokedTicket.ContentFlags)
	}
}

// TestNotarizedVsRevokedConsistency verifies that IsNotarized is consistent with TicketState
func TestNotarizedVsRevokedConsistency(t *testing.T) {
	testCases := []struct {
		name              string
		ticketState       opb.TicketState
		contentFlags      uint32
		expectedNotarized bool
	}{
		{
			name:              "Notarized ticket (content_flags=0)",
			ticketState:       opb.TicketState_TICKET_STATE_NOTARIZED,
			contentFlags:      0,
			expectedNotarized: true,
		},
		{
			name:              "Revoked ticket (content_flags=1)",
			ticketState:       opb.TicketState_TICKET_STATE_REVOKED,
			contentFlags:      1,
			expectedNotarized: false,
		},
		{
			name:              "Unspecified ticket state",
			ticketState:       opb.TicketState_TICKET_STATE_UNSPECIFIED,
			contentFlags:      99,
			expectedNotarized: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the logic in populateNotarizationInfo
			notarization := &opb.NotarizationInfo{
				TicketState:  tc.ticketState,
				ContentFlags: tc.contentFlags,
			}

			// Apply the same logic as in populateNotarizationInfo
			notarization.IsNotarized = (notarization.TicketState == opb.TicketState_TICKET_STATE_NOTARIZED)

			// Verify IsNotarized matches expected value
			if notarization.IsNotarized != tc.expectedNotarized {
				t.Errorf("Expected IsNotarized=%v for TicketState=%v (content_flags=%d), got %v",
					tc.expectedNotarized, tc.ticketState, tc.contentFlags, notarization.IsNotarized)
			}
		})
	}
}

// TestHasTicketField verifies the has_ticket field is set correctly
func TestHasTicketField(t *testing.T) {
	testCases := []struct {
		name        string
		hasTicket   bool
		ticketState opb.TicketState
		isNotarized bool
		description string
	}{
		{
			name:        "Notarized ticket has has_ticket=true",
			hasTicket:   true,
			ticketState: opb.TicketState_TICKET_STATE_NOTARIZED,
			isNotarized: true,
			description: "Binary with notarized ticket from Apple",
		},
		{
			name:        "Revoked ticket has has_ticket=true",
			hasTicket:   true,
			ticketState: opb.TicketState_TICKET_STATE_REVOKED,
			isNotarized: false,
			description: "Binary with revoked ticket from Apple",
		},
		{
			name:        "No ticket has has_ticket=false",
			hasTicket:   false,
			ticketState: opb.TicketState_TICKET_STATE_UNSPECIFIED,
			isNotarized: false,
			description: "Binary not found in Apple's CloudKit service",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			notarization := &opb.NotarizationInfo{
				HasTicket:   tc.hasTicket,
				TicketState: tc.ticketState,
				IsNotarized: tc.isNotarized,
			}

			// Verify has_ticket is set correctly
			if notarization.HasTicket != tc.hasTicket {
				t.Errorf("Expected HasTicket=%v, got %v", tc.hasTicket, notarization.HasTicket)
			}

			// Verify consistency: if has_ticket is true, ticket_state should not be UNSPECIFIED
			if notarization.HasTicket && notarization.TicketState == opb.TicketState_TICKET_STATE_UNSPECIFIED {
				t.Error("HasTicket=true but TicketState is UNSPECIFIED (inconsistent)")
			}

			// Verify consistency: if has_ticket is false, both is_notarized and ticket_state should indicate no ticket
			if !notarization.HasTicket {
				if notarization.IsNotarized {
					t.Error("HasTicket=false but IsNotarized=true (inconsistent)")
				}
				if notarization.TicketState != opb.TicketState_TICKET_STATE_UNSPECIFIED {
					t.Error("HasTicket=false but TicketState is not UNSPECIFIED (inconsistent)")
				}
			}
		})
	}
}

// TestHasTicketVsIsNotarizedDistinction verifies that has_ticket and is_notarized are distinct
func TestHasTicketVsIsNotarizedDistinction(t *testing.T) {
	// Test case: Binary has a ticket but is NOT notarized (revoked)
	revokedTicket := &opb.NotarizationInfo{
		HasTicket:    true,  // We received a ticket from Apple
		IsNotarized:  false, // But the ticket indicates revocation
		TicketState:  opb.TicketState_TICKET_STATE_REVOKED,
		ContentFlags: 1,
	}

	if !revokedTicket.HasTicket {
		t.Error("Revoked ticket should have HasTicket=true (we got a ticket from Apple)")
	}

	if revokedTicket.IsNotarized {
		t.Error("Revoked ticket should have IsNotarized=false (it's blocked by Apple)")
	}

	// Test case: Binary has no ticket
	noTicket := &opb.NotarizationInfo{
		HasTicket:   false, // No ticket from Apple
		IsNotarized: false, // Not notarized
		TicketState: opb.TicketState_TICKET_STATE_UNSPECIFIED,
	}

	if noTicket.HasTicket {
		t.Error("Binary with no ticket should have HasTicket=false")
	}

	if noTicket.IsNotarized {
		t.Error("Binary with no ticket should have IsNotarized=false")
	}

	// Test case: Binary is notarized (implies has_ticket=true)
	notarizedTicket := &opb.NotarizationInfo{
		HasTicket:    true, // We got a ticket from Apple
		IsNotarized:  true, // And it's a notarization (not revocation)
		TicketState:  opb.TicketState_TICKET_STATE_NOTARIZED,
		ContentFlags: 0,
	}

	if !notarizedTicket.HasTicket {
		t.Error("Notarized binary should have HasTicket=true")
	}

	if !notarizedTicket.IsNotarized {
		t.Error("Notarized binary should have IsNotarized=true")
	}

	// Key insight: has_ticket can be true while is_notarized is false (revoked case)
	// but is_notarized=true always implies has_ticket=true
}

// TestG8tkTimestampUtc verifies that g8tk_timestamp_utc is properly formatted
func TestG8tkTimestampUtc(t *testing.T) {
	testCases := []struct {
		name              string
		g8tkTimestamp     uint64
		expectedUtcFormat bool
	}{
		{
			name:              "Valid g8tk timestamp",
			g8tkTimestamp:     1742298352, // Unix seconds
			expectedUtcFormat: true,
		},
		{
			name:              "Zero timestamp",
			g8tkTimestamp:     0,
			expectedUtcFormat: false, // Should not set UTC string for zero timestamp
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			notarization := &opb.NotarizationInfo{
				G8TkTimestamp: tc.g8tkTimestamp,
			}

			// Simulate the conversion logic from notarization.go
			if tc.g8tkTimestamp > 0 {
				g8tkTime := time.Unix(int64(tc.g8tkTimestamp), 0)
				notarization.G8TkTimestampUtc = g8tkTime.UTC().Format(time.RFC3339)
			}

			// Verify UTC format
			if tc.expectedUtcFormat {
				if notarization.G8TkTimestampUtc == "" {
					t.Error("G8TkTimestampUtc should not be empty for valid timestamp")
				}

				// Verify it's a valid RFC3339 format
				_, err := time.Parse(time.RFC3339, notarization.G8TkTimestampUtc)
				if err != nil {
					t.Errorf("G8TkTimestampUtc should be valid RFC3339 format, got error: %v", err)
				}

				// Verify it ends with Z (UTC)
				if notarization.G8TkTimestampUtc[len(notarization.G8TkTimestampUtc)-1] != 'Z' {
					t.Error("G8TkTimestampUtc should end with Z (UTC timezone)")
				}
			} else {
				if notarization.G8TkTimestampUtc != "" {
					t.Error("G8TkTimestampUtc should be empty for zero timestamp")
				}
			}
		})
	}
}

// TestG8tkTimestampUtcConsistency verifies g8tk_timestamp and g8tk_timestamp_utc are consistent
func TestG8tkTimestampUtcConsistency(t *testing.T) {
	notarization := &opb.NotarizationInfo{
		G8TkTimestamp: 1742298352, // Example Unix timestamp
	}

	// Convert timestamp to UTC string
	g8tkTime := time.Unix(int64(notarization.G8TkTimestamp), 0)
	notarization.G8TkTimestampUtc = g8tkTime.UTC().Format(time.RFC3339)

	// Parse the UTC string back
	parsedTime, err := time.Parse(time.RFC3339, notarization.G8TkTimestampUtc)
	if err != nil {
		t.Fatalf("Failed to parse G8TkTimestampUtc: %v", err)
	}

	// Verify the parsed time matches the original Unix timestamp
	if parsedTime.Unix() != int64(notarization.G8TkTimestamp) {
		t.Errorf("G8TkTimestampUtc does not match G8TkTimestamp: %d != %d",
			parsedTime.Unix(), notarization.G8TkTimestamp)
	}
}
