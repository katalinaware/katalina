package main

import (
	"testing"

	opb "github.com/appsworld/katalinaware/protos"
)

func TestGetSwiftClassesEmpty(t *testing.T) {
	// Test with a nil MachoReader (edge case)
	mockReader := &MachoReader{MachoReader: nil}
	
	// This should return empty Swift features without panicking
	swiftFeat := getSwiftClasses(mockReader)
	
	if swiftFeat == nil {
		t.Fatal("getSwiftClasses returned nil")
	}
	
	if len(swiftFeat.TypeNames) != 0 {
		t.Errorf("Expected 0 type names, got %d", len(swiftFeat.TypeNames))
	}
	
	if swiftFeat.TypeHash != "" {
		t.Errorf("Expected empty type hash, got %s", swiftFeat.TypeHash)
	}
}

func TestSwiftFeaturesStructure(t *testing.T) {
	// Test that we can create SwiftFeatures protobuf structures
	swiftFeat := &opb.SwiftFeatures{
		TypeNames: []string{"TestType", "AnotherType"},
		TypeHash:  "ghi789",
	}
	
	if len(swiftFeat.TypeNames) != 2 {
		t.Errorf("SwiftFeatures has %d type names, expected 2", len(swiftFeat.TypeNames))
	}
	
	if swiftFeat.TypeNames[0] != "TestType" {
		t.Errorf("Type name = %s, expected TestType", swiftFeat.TypeNames[0])
	}
	
	if swiftFeat.TypeHash != "ghi789" {
		t.Errorf("Type hash = %s, expected ghi789", swiftFeat.TypeHash)
	}
}

func TestEmptySwiftFeatures(t *testing.T) {
	// Test that emptySwiftFeatures is properly initialized
	if emptySwiftFeatures == nil {
		t.Fatal("emptySwiftFeatures is nil")
	}
	
	if len(emptySwiftFeatures.TypeNames) != 0 {
		t.Errorf("emptySwiftFeatures has %d type names, expected 0", len(emptySwiftFeatures.TypeNames))
	}
	
	if emptySwiftFeatures.TypeHash != "" {
		t.Errorf("emptySwiftFeatures type hash = %s, expected empty", emptySwiftFeatures.TypeHash)
	}
}

func TestModelFeatHasSwiftFeatures(t *testing.T) {
	// Test that emptyModelFeat includes SwiftFeatures
	if emptyModelFeat == nil {
		t.Fatal("emptyModelFeat is nil")
	}
	
	if emptyModelFeat.SwiftFeatures == nil {
		t.Fatal("emptyModelFeat.SwiftFeatures is nil")
	}
	
	// Should be the same instance as emptySwiftFeatures
	if emptyModelFeat.SwiftFeatures != emptySwiftFeatures {
		t.Error("emptyModelFeat.SwiftFeatures is not the same instance as emptySwiftFeatures")
	}
}