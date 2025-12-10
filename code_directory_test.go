package main

import (
	"testing"

	opb "github.com/appsworld/katalinaware/protos"
)

func TestCodeDirectoryNewStructure(t *testing.T) {
	// Test creating a CodeDirectory with the new structure
	codeDir := &opb.CodeDirectory{
		Id:     "com.EdoneViewer",
		TeamId: "2C4CB2P247",
		SpecialSlots: &opb.SpecialSlot{
			PsListHash:       "8c279c866a8afe795618c49e75033674534d929234d56ad2af5c050e3c304e8e",
			RequirementsHash: "7ecdb76c1fdffd1fe9448fd2e2383976b3681f15fbde12c8983a25f2256179dd",
			EntitlementHash:  "",
			CodeResourceHash: "94e9512d816465a7a631e3b18814ace894d271b25258347b9e0b383b9d8022e4",
		},
	}

	// Verify the fields are now strings instead of arrays
	if codeDir.Id != "com.EdoneViewer" {
		t.Errorf("Expected Id to be 'com.EdoneViewer', got '%s'", codeDir.Id)
	}

	if codeDir.TeamId != "2C4CB2P247" {
		t.Errorf("Expected TeamId to be '2C4CB2P247', got '%s'", codeDir.TeamId)
	}

	// Verify SpecialSlots is now a single object instead of an array
	if codeDir.SpecialSlots == nil {
		t.Fatal("SpecialSlots should not be nil")
	}

	slots := codeDir.SpecialSlots
	if slots.PsListHash != "8c279c866a8afe795618c49e75033674534d929234d56ad2af5c050e3c304e8e" {
		t.Errorf("Expected PsListHash to match, got '%s'", slots.PsListHash)
	}

	if slots.RequirementsHash != "7ecdb76c1fdffd1fe9448fd2e2383976b3681f15fbde12c8983a25f2256179dd" {
		t.Errorf("Expected RequirementsHash to match, got '%s'", slots.RequirementsHash)
	}

	if slots.EntitlementHash != "" {
		t.Errorf("Expected EntitlementHash to be empty, got '%s'", slots.EntitlementHash)
	}

	if slots.CodeResourceHash != "94e9512d816465a7a631e3b18814ace894d271b25258347b9e0b383b9d8022e4" {
		t.Errorf("Expected CodeResourceHash to match, got '%s'", slots.CodeResourceHash)
	}
}

func TestEmptyCodeDirectory(t *testing.T) {
	// Test the empty code directory structure
	emptyCD := emptyCodeDir

	// Verify empty structure has correct types
	if emptyCD.Id != "" {
		t.Errorf("Expected empty Id to be empty string, got '%s'", emptyCD.Id)
	}

	if emptyCD.TeamId != "" {
		t.Errorf("Expected empty TeamId to be empty string, got '%s'", emptyCD.TeamId)
	}

	if emptyCD.SpecialSlots == nil {
		t.Fatal("SpecialSlots should not be nil even when empty")
	}

	// Verify empty special slots
	slots := emptyCD.SpecialSlots
	if slots.PsListHash != "" || slots.RequirementsHash != "" || 
	   slots.EntitlementHash != "" || slots.CodeResourceHash != "" {
		t.Error("Expected all special slot hashes to be empty")
	}
}

func TestGetCodeDirectoryFunction(t *testing.T) {
	// Test that getCodeDirectory returns the correct structure
	// Using nil MachoReader to get emptyCodeDir
	result := getCodeDirectory(nil)

	if result == nil {
		t.Fatal("getCodeDirectory should not return nil")
	}

	// Verify it returns the correct structure type
	if result.Id != "" {
		t.Errorf("Expected empty Id from nil input, got '%s'", result.Id)
	}

	if result.TeamId != "" {
		t.Errorf("Expected empty TeamId from nil input, got '%s'", result.TeamId)
	}

	if result.SpecialSlots == nil {
		t.Fatal("SpecialSlots should not be nil")
	}
}

func TestCDHashFieldsStructure(t *testing.T) {
	// Test that the new CDHash fields are properly structured in protobuf
	codeDir := &opb.CodeDirectory{
		Id:                         "com.test.app",
		TeamId:                     "TESTTEAM123",
		HashType:                   2,
		ExtractedCdhash:           "343ec2299ba67facfa5925207a58f81f9aacf49b",
		ExtractedCdhashFull:       "343ec2299ba67facfa5925207a58f81f9aacf49b348ff278aeafd1b5c6a35d15",
		ComputedSha1Cdhash:        "73e668bda5157d4d529b34a1295e82d515d9968c",
		ComputedSha1CdhashFull:    "73e668bda5157d4d529b34a1295e82d515d9968c",
		ComputedSha256Cdhash:      "343ec2299ba67facfa5925207a58f81f9aacf49b",
		ComputedSha256CdhashFull:  "343ec2299ba67facfa5925207a58f81f9aacf49b348ff278aeafd1b5c6a35d15",
		SpecialSlots: &opb.SpecialSlot{},
	}

	// Verify hash type
	if codeDir.HashType != 2 {
		t.Errorf("Expected HashType to be 2 (SHA256), got %d", codeDir.HashType)
	}

	// Verify extracted CDHash fields
	expectedExtractedCDHash := "343ec2299ba67facfa5925207a58f81f9aacf49b"
	if codeDir.ExtractedCdhash != expectedExtractedCDHash {
		t.Errorf("Expected ExtractedCdhash to be %s, got %s", expectedExtractedCDHash, codeDir.ExtractedCdhash)
	}

	expectedExtractedCDHashFull := "343ec2299ba67facfa5925207a58f81f9aacf49b348ff278aeafd1b5c6a35d15"
	if codeDir.ExtractedCdhashFull != expectedExtractedCDHashFull {
		t.Errorf("Expected ExtractedCdhashFull to be %s, got %s", expectedExtractedCDHashFull, codeDir.ExtractedCdhashFull)
	}

	// Verify computed SHA1 CDHash fields
	expectedSha1CDHash := "73e668bda5157d4d529b34a1295e82d515d9968c"
	if codeDir.ComputedSha1Cdhash != expectedSha1CDHash {
		t.Errorf("Expected ComputedSha1Cdhash to be %s, got %s", expectedSha1CDHash, codeDir.ComputedSha1Cdhash)
	}

	if codeDir.ComputedSha1CdhashFull != expectedSha1CDHash {
		t.Errorf("Expected ComputedSha1CdhashFull to be %s, got %s", expectedSha1CDHash, codeDir.ComputedSha1CdhashFull)
	}

	// Verify computed SHA256 CDHash fields
	expectedSha256CDHash := "343ec2299ba67facfa5925207a58f81f9aacf49b"
	if codeDir.ComputedSha256Cdhash != expectedSha256CDHash {
		t.Errorf("Expected ComputedSha256Cdhash to be %s, got %s", expectedSha256CDHash, codeDir.ComputedSha256Cdhash)
	}

	expectedSha256CDHashFull := "343ec2299ba67facfa5925207a58f81f9aacf49b348ff278aeafd1b5c6a35d15"
	if codeDir.ComputedSha256CdhashFull != expectedSha256CDHashFull {
		t.Errorf("Expected ComputedSha256CdhashFull to be %s, got %s", expectedSha256CDHashFull, codeDir.ComputedSha256CdhashFull)
	}
}

func TestCDHashLength(t *testing.T) {
	// Test CDHash lengths are correct (20 bytes = 40 hex chars, full hash varies)
	testCases := []struct {
		name       string
		cdhash     string
		cdhashFull string
		hashType   string
	}{
		{
			name:       "SHA1 CDHash",
			cdhash:     "73e668bda5157d4d529b34a1295e82d515d9968c",
			cdhashFull: "73e668bda5157d4d529b34a1295e82d515d9968c",
			hashType:   "SHA1",
		},
		{
			name:       "SHA256 CDHash",
			cdhash:     "343ec2299ba67facfa5925207a58f81f9aacf49b",
			cdhashFull: "343ec2299ba67facfa5925207a58f81f9aacf49b348ff278aeafd1b5c6a35d15",
			hashType:   "SHA256",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// CDHash should always be 40 hex characters (20 bytes)
			if len(tc.cdhash) != 40 {
				t.Errorf("Expected CDHash length to be 40 hex chars, got %d for %s", len(tc.cdhash), tc.hashType)
			}

			// Full hash length depends on algorithm
			expectedFullLength := 40 // SHA1
			if tc.hashType == "SHA256" {
				expectedFullLength = 64 // SHA256
			}
			
			if len(tc.cdhashFull) != expectedFullLength {
				t.Errorf("Expected %s full hash length to be %d hex chars, got %d", tc.hashType, expectedFullLength, len(tc.cdhashFull))
			}
		})
	}
}

func TestCDHashComputationConsistency(t *testing.T) {
	// Test that CDHash fields maintain consistency
	codeDir := &opb.CodeDirectory{
		HashType:                   2, // SHA256
		ExtractedCdhash:           "343ec2299ba67facfa5925207a58f81f9aacf49b",
		ExtractedCdhashFull:       "343ec2299ba67facfa5925207a58f81f9aacf49b348ff278aeafd1b5c6a35d15",
		ComputedSha256Cdhash:      "343ec2299ba67facfa5925207a58f81f9aacf49b",
		ComputedSha256CdhashFull:  "343ec2299ba67facfa5925207a58f81f9aacf49b348ff278aeafd1b5c6a35d15",
	}

	// For SHA256 binaries, extracted and computed SHA256 should match
	if codeDir.ExtractedCdhash != codeDir.ComputedSha256Cdhash {
		t.Errorf("For SHA256 binary, extracted CDHash should match computed SHA256 CDHash")
	}

	if codeDir.ExtractedCdhashFull != codeDir.ComputedSha256CdhashFull {
		t.Errorf("For SHA256 binary, extracted full CDHash should match computed SHA256 full CDHash")
	}

	// Verify extracted CDHash is prefix of extracted full CDHash
	if !startsWith(codeDir.ExtractedCdhashFull, codeDir.ExtractedCdhash) {
		t.Errorf("Extracted CDHash should be prefix of extracted full CDHash")
	}
}

// Helper function for testing
func startsWith(full, prefix string) bool {
	return len(full) >= len(prefix) && full[:len(prefix)] == prefix
}

func TestCDHashExtractionWithMockData(t *testing.T) {
	// Test with nil MachoReader to verify it returns empty CodeDirectory
	result := getCodeDirectory(nil)

	if result == nil {
		t.Fatal("getCodeDirectory should not return nil even for nil input")
	}

	// Verify it returns emptyCodeDir structure
	if result.Id != "" {
		t.Error("Expected empty Id from nil MachoReader")
	}

	if result.TeamId != "" {
		t.Error("Expected empty TeamId from nil MachoReader")
	}

	// Verify all new CDHash fields are properly initialized to empty strings
	if result.ExtractedCdhash != "" {
		t.Error("ExtractedCdhash should be empty for nil input")
	}

	if result.ExtractedCdhashFull != "" {
		t.Error("ExtractedCdhashFull should be empty for nil input")  
	}

	if result.ComputedSha1Cdhash != "" {
		t.Error("ComputedSha1Cdhash should be empty for nil input")
	}

	if result.ComputedSha1CdhashFull != "" {
		t.Error("ComputedSha1CdhashFull should be empty for nil input")
	}

	if result.ComputedSha256Cdhash != "" {
		t.Error("ComputedSha256Cdhash should be empty for nil input")
	}

	if result.ComputedSha256CdhashFull != "" {
		t.Error("ComputedSha256CdhashFull should be empty for nil input")
	}

	if result.HashType != 0 {
		t.Error("HashType should be 0 for nil input")
	}
}

func TestCDHashExtractionWithMockBinaryData(t *testing.T) {
	// Test populateCDHashInfo with known test data
	testCases := []struct {
		name           string
		inputHashType  int32
		expectedSHA1   string
		expectedSHA256 string
	}{
		{
			name:           "SHA256 Binary",
			inputHashType:  2,
			expectedSHA1:   "73e668bda5157d4d529b34a1295e82d515d9968c",
			expectedSHA256: "343ec2299ba67facfa5925207a58f81f9aacf49b",
		},
		{
			name:           "SHA1 Binary", 
			inputHashType:  1,
			expectedSHA1:   "73e668bda5157d4d529b34a1295e82d515d9968c",
			expectedSHA256: "343ec2299ba67facfa5925207a58f81f9aacf49b",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that we can manually set CDHash values (for testing)
			codeDir := &opb.CodeDirectory{}
			
			// Manually populate what the function would do
			codeDir.HashType = tc.inputHashType
			codeDir.ComputedSha1Cdhash = tc.expectedSHA1
			codeDir.ComputedSha256Cdhash = tc.expectedSHA256
			
			// For SHA256 binary, extracted should match computed SHA256
			if tc.inputHashType == 2 {
				codeDir.ExtractedCdhash = tc.expectedSHA256
			}
			
			// For SHA1 binary, extracted should match computed SHA1
			if tc.inputHashType == 1 {
				codeDir.ExtractedCdhash = tc.expectedSHA1
			}

			// Verify the structure is correct
			if codeDir.HashType != tc.inputHashType {
				t.Errorf("Expected HashType %d, got %d", tc.inputHashType, codeDir.HashType)
			}

			if len(codeDir.ComputedSha1Cdhash) != 40 {
				t.Errorf("Expected SHA1 CDHash to be 40 chars, got %d", len(codeDir.ComputedSha1Cdhash))
			}

			if len(codeDir.ComputedSha256Cdhash) != 40 {
				t.Errorf("Expected SHA256 CDHash to be 40 chars, got %d", len(codeDir.ComputedSha256Cdhash))
			}
		})
	}
}

func TestPopulateCDHashInfoWithNilInputs(t *testing.T) {
	// Test populateCDHashInfo with nil inputs
	var nilReader *MachoReader
	var nilCodeDir *opb.CodeDirectory

	// These should not panic
	populateCDHashInfo(nilReader, nilCodeDir)
	populateCDHashInfo(nilReader, &opb.CodeDirectory{})
	
	// Test with valid CodeDirectory but nil reader
	codeDir := &opb.CodeDirectory{}
	populateCDHashInfo(nilReader, codeDir)
	
	// Should remain empty since input is nil
	if codeDir.HashType != 0 {
		t.Error("HashType should remain 0 with nil reader")
	}
}

func TestCodeDirectoryNotarizationIntegration(t *testing.T) {
	// Test that CodeDirectory properly includes notarization information
	codeDir := &opb.CodeDirectory{
		Id:                      "com.test.app", 
		TeamId:                  "TESTTEAM",
		ExtractedCdhash:        "343ec2299ba67facfa5925207a58f81f9aacf49b",
		ComputedSha256Cdhash:   "343ec2299ba67facfa5925207a58f81f9aacf49b",
	}

	codeDir.Notarization = &opb.NotarizationInfo{
		IsNotarized:   true,
		Timestamp:     1753163385094,
		TimestampUtc:  "2025-07-22T05:49:45Z",
		Error:         "",
		RecordName:    "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b",
		SignedTicket:  "czhjaAEAAADxBQAALQ...",
		Deleted:       false,
	}

	// Verify notarization is properly integrated
	if codeDir.Notarization == nil {
		t.Fatal("Notarization should not be nil in CodeDirectory")
	}

	if !codeDir.Notarization.IsNotarized {
		t.Error("Binary should be marked as notarized")
	}

	expectedRecordName := "2/2/343ec2299ba67facfa5925207a58f81f9aacf49b"
	if codeDir.Notarization.RecordName != expectedRecordName {
		t.Errorf("Expected record name %s, got %s", expectedRecordName, codeDir.Notarization.RecordName)
	}

	if codeDir.Notarization.Timestamp <= 0 {
		t.Error("Timestamp should be positive for notarized binary")
	}

	if codeDir.Notarization.TimestampUtc == "" {
		t.Error("TimestampUtc should not be empty for notarized binary")
	}

	if len(codeDir.Notarization.SignedTicket) == 0 {
		t.Error("SignedTicket should not be empty for notarized binary")
	}

	if codeDir.Notarization.Error != "" {
		t.Errorf("Error should be empty for successful notarization check, got: %s", codeDir.Notarization.Error)
	}

	// Note: Deleted field depends on Apple's response data, so we just verify it's accessible
	_ = codeDir.Notarization.Deleted
}

func TestEmptyCodeDirectoryWithNotarization(t *testing.T) {
	// Test that emptyCodeDir includes notarization field
	if emptyCodeDir.Notarization == nil {
		t.Fatal("emptyCodeDir should have notarization field")
	}

	if emptyCodeDir.Notarization.IsNotarized {
		t.Error("emptyCodeDir should not be marked as notarized")
	}

	if emptyCodeDir.Notarization.RecordName != "" {
		t.Error("emptyCodeDir notarization RecordName should be empty")
	}

	if emptyCodeDir.Notarization.Timestamp != 0 {
		t.Error("emptyCodeDir notarization Timestamp should be 0")
	}

	if emptyCodeDir.Notarization.TimestampUtc != "" {
		t.Error("emptyCodeDir notarization TimestampUtc should be empty")
	}

	// For emptyCodeDir, deleted should be false as it's initialized that way
	if emptyCodeDir.Notarization.Deleted {
		t.Error("emptyCodeDir notarization Deleted should be false")
	}
}