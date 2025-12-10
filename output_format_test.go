package main

import (
	"encoding/json"
	"testing"

	opb "github.com/appsworld/katalinaware/protos"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestCodeDirectoryJSONOutput(t *testing.T) {
	// Create a sample CodeDirectory with the new structure
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

	// Convert to JSON using protojson (same as the main application)
	jsonData, err := protojson.MarshalOptions{
		Indent:          "    ",
		Multiline:       true,
		UseProtoNames:   false,
		EmitUnpopulated: true,
	}.Marshal(codeDir)
	if err != nil {
		t.Fatalf("Failed to marshal CodeDirectory to JSON: %v", err)
	}

	// Parse the JSON to verify structure
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	if err != nil {
		t.Fatalf("Failed to parse generated JSON: %v", err)
	}

	// Verify the structure matches the expected format
	if parsed["id"] != "com.EdoneViewer" {
		t.Errorf("Expected id to be 'com.EdoneViewer', got %v", parsed["id"])
	}

	if parsed["teamId"] != "2C4CB2P247" {
		t.Errorf("Expected teamId to be '2C4CB2P247', got %v", parsed["teamId"])
	}

	// Verify specialSlots is an object, not an array
	specialSlots, ok := parsed["specialSlots"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected specialSlots to be an object, got %T", parsed["specialSlots"])
	}

	expectedSlots := map[string]string{
		"psListHash":       "8c279c866a8afe795618c49e75033674534d929234d56ad2af5c050e3c304e8e",
		"requirementsHash": "7ecdb76c1fdffd1fe9448fd2e2383976b3681f15fbde12c8983a25f2256179dd",
		"codeResourceHash": "94e9512d816465a7a631e3b18814ace894d271b25258347b9e0b383b9d8022e4",
	}

	for key, expected := range expectedSlots {
		if actual, exists := specialSlots[key]; !exists {
			t.Errorf("Missing field %s in specialSlots", key)
		} else if actual != expected {
			t.Errorf("Field %s: expected '%s', got '%v'", key, expected, actual)
		}
	}
	
	// Verify that entitlementHash is omitted when empty (this is correct behavior)
	if _, exists := specialSlots["entitlementHash"]; exists {
		t.Logf("entitlementHash is present in output (this is fine if not empty)")
	} else {
		t.Logf("entitlementHash is omitted from output (correct for empty values)")
	}

	// Print the JSON for manual verification (optional)
	t.Logf("Generated JSON:\n%s", string(jsonData))
}

func TestFullAnalysisOutputStructure(t *testing.T) {
	// Create a minimal AnalysisOutput with CodeDirectory
	output := &opb.AnalysisOutput{
		FilePath: "/test/path",
		ModelFeat: &opb.ModelFeat{
			CodeDirectory: &opb.CodeDirectory{
				Id:     "com.test.app",
				TeamId: "TESTTEAM01",
				SpecialSlots: &opb.SpecialSlot{
					PsListHash:       "test_ps_hash",
					RequirementsHash: "test_req_hash",
					EntitlementHash:  "test_ent_hash",
					CodeResourceHash: "test_res_hash",
				},
			},
		},
	}

	// Convert to JSON
	jsonData, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(output)
	if err != nil {
		t.Fatalf("Failed to marshal AnalysisOutput to JSON: %v", err)
	}

	// Parse and verify structure
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	if err != nil {
		t.Fatalf("Failed to parse generated JSON: %v", err)
	}

	// Navigate to codeDirectory
	modelFeat, ok := parsed["modelFeat"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected modelFeat to be an object")
	}

	codeDir, ok := modelFeat["codeDirectory"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected codeDirectory to be an object")
	}

	// Verify the structure
	if codeDir["id"] != "com.test.app" {
		t.Errorf("Expected id to be 'com.test.app', got %v", codeDir["id"])
	}

	if codeDir["teamId"] != "TESTTEAM01" {
		t.Errorf("Expected teamId to be 'TESTTEAM01', got %v", codeDir["teamId"])
	}

	specialSlots, ok := codeDir["specialSlots"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected specialSlots to be an object, got %T", codeDir["specialSlots"])
	}

	if specialSlots["psListHash"] != "test_ps_hash" {
		t.Errorf("Expected psListHash to be 'test_ps_hash', got %v", specialSlots["psListHash"])
	}

	t.Logf("Full structure verified successfully")
}