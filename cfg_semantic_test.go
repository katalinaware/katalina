package main

import (
	"fmt"
	"strings"
	"testing"

	opb "github.com/appsworld/katalinaware/protos"
)

func TestNewSemanticAnalyzer(t *testing.T) {
	analyzer := NewSemanticAnalyzer()
	
	if analyzer == nil {
		t.Fatal("NewSemanticAnalyzer() returned nil")
	}
	
	if analyzer.cryptoPatterns == nil {
		t.Error("NewSemanticAnalyzer() did not initialize cryptoPatterns")
	}
	
	if analyzer.apiPatterns == nil {
		t.Error("NewSemanticAnalyzer() did not initialize apiPatterns")
	}
	
	// Test that crypto patterns are properly initialized
	if !analyzer.cryptoPatterns["AES"] {
		t.Error("NewSemanticAnalyzer() did not initialize AES crypto pattern")
	}
	
	if !analyzer.cryptoPatterns["XOR"] {
		t.Error("NewSemanticAnalyzer() did not initialize XOR crypto pattern")
	}
	
	// Test that API patterns are properly initialized
	if !analyzer.apiPatterns["CALL"] {
		t.Error("NewSemanticAnalyzer() did not initialize CALL API pattern")
	}
}

func TestSemanticAnalyzer_classifyInstruction(t *testing.T) {
	analyzer := NewSemanticAnalyzer()
	
	tests := []struct {
		name         string
		instruction  *opb.Instruction
		expectedCat  string
		expectedOp   string
		expectedCond bool
		expectedAPI  bool
		expectedCryp bool
	}{
		{
			name:         "Arithmetic instruction",
			instruction:  &opb.Instruction{Opcode: "ADD", Operands: "rax, rbx"},
			expectedCat:  "ARITHMETIC",
			expectedOp:   "ADD",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: false,
		},
		{
			name:         "Memory instruction",
			instruction:  &opb.Instruction{Opcode: "MOV", Operands: "rax, [rbp+8]"},
			expectedCat:  "MEMORY",
			expectedOp:   "MOV",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: false,
		},
		{
			name:         "Conditional control flow",
			instruction:  &opb.Instruction{Opcode: "JE", Operands: "0x1000"},
			expectedCat:  "CONTROL",
			expectedOp:   "JE",
			expectedCond: true,
			expectedAPI:  false,
			expectedCryp: false,
		},
		{
			name:         "Unconditional control flow",
			instruction:  &opb.Instruction{Opcode: "JMP", Operands: "0x2000"},
			expectedCat:  "CONTROL",
			expectedOp:   "JMP",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: false,
		},
		{
			name:         "Stack instruction",
			instruction:  &opb.Instruction{Opcode: "PUSH", Operands: "rbp"},
			expectedCat:  "STACK",
			expectedOp:   "PUSH",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: false,
		},
		{
			name:         "Bitwise instruction",
			instruction:  &opb.Instruction{Opcode: "XOR", Operands: "rax, rax"},
			expectedCat:  "CRYPTO", // XOR is classified as crypto
			expectedOp:   "XOR",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: true,
		},
		{
			name:         "Floating point instruction",
			instruction:  &opb.Instruction{Opcode: "FADD", Operands: "st0, st1"},
			expectedCat:  "FLOAT",
			expectedOp:   "FADD",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: false,
		},
		{
			name:         "API call instruction",
			instruction:  &opb.Instruction{Opcode: "CALL", Operands: "malloc@plt"},
			expectedCat:  "CONTROL",
			expectedOp:   "CALL",
			expectedCond: false,
			expectedAPI:  true,
			expectedCryp: false,
		},
		{
			name:         "Crypto instruction (AES)",
			instruction:  &opb.Instruction{Opcode: "AESENC", Operands: "xmm0, xmm1"},
			expectedCat:  "CRYPTO",
			expectedOp:   "AESENC",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: true,
		},
		{
			name:         "Unknown instruction",
			instruction:  &opb.Instruction{Opcode: "UNKNOWN", Operands: ""},
			expectedCat:  "OTHER",
			expectedOp:   "UNKNOWN",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: false,
		},
		{
			name:         "Crypto pattern in operands",
			instruction:  &opb.Instruction{Opcode: "MOV", Operands: "rax, aes_key"},
			expectedCat:  "CRYPTO",
			expectedOp:   "MOV",
			expectedCond: false,
			expectedAPI:  false,
			expectedCryp: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.classifyInstruction(tt.instruction)
			
			if result.Category != tt.expectedCat {
				t.Errorf("classifyInstruction().Category = %s, expected %s", 
					result.Category, tt.expectedCat)
			}
			
			if result.Operation != tt.expectedOp {
				t.Errorf("classifyInstruction().Operation = %s, expected %s", 
					result.Operation, tt.expectedOp)
			}
			
			if result.IsCondition != tt.expectedCond {
				t.Errorf("classifyInstruction().IsCondition = %v, expected %v", 
					result.IsCondition, tt.expectedCond)
			}
			
			if result.IsAPI != tt.expectedAPI {
				t.Errorf("classifyInstruction().IsAPI = %v, expected %v", 
					result.IsAPI, tt.expectedAPI)
			}
			
			if result.IsCrypto != tt.expectedCryp {
				t.Errorf("classifyInstruction().IsCrypto = %v, expected %v", 
					result.IsCrypto, tt.expectedCryp)
			}
			
			// Test normalized format - calculate actual operand count
			operandCount := "0"
			if tt.instruction.Operands != "" {
				// Count actual operands by splitting on comma
				operands := strings.Split(tt.instruction.Operands, ",")
				operandCount = fmt.Sprintf("%d", len(operands))
			}
			expectedNormalized := tt.expectedCat + ":" + tt.expectedOp + ":" + operandCount
			if result.Normalized != expectedNormalized {
				t.Errorf("classifyInstruction().Normalized = %s, expected %s", 
					result.Normalized, expectedNormalized)
			}
		})
	}
}

func TestSemanticAnalyzer_normalizeBasicBlock(t *testing.T) {
	analyzer := NewSemanticAnalyzer()
	
	block := &opb.BasicBlock{
		Id:           "test_block",
		StartAddress: "0x1000",
		EndAddress:   "0x1010",
		Instructions: []*opb.Instruction{
			{Address: "0x1000", Opcode: "PUSH", Operands: "rbp"},
			{Address: "0x1001", Opcode: "MOV", Operands: "rbp, rsp"},
			{Address: "0x1002", Opcode: "XOR", Operands: "rax, rax"},
			{Address: "0x1003", Opcode: "CALL", Operands: "malloc@plt"},
		},
	}
	
	result := analyzer.normalizeBasicBlock(block)
	
	if result.ID != "test_block" {
		t.Errorf("normalizeBasicBlock().ID = %s, expected test_block", result.ID)
	}
	
	if len(result.InstructionTypes) != 4 {
		t.Errorf("normalizeBasicBlock() has %d instruction types, expected 4", len(result.InstructionTypes))
	}
	
	// Check that semantic hash is generated
	if result.SemanticHash == "" {
		t.Error("normalizeBasicBlock().SemanticHash is empty")
	}
	
	// Check that instruction types are populated
	if len(result.InstructionTypes) == 0 {
		t.Error("normalizeBasicBlock().InstructionTypes is empty")
	}
	
	// Check that API calls are detected
	if len(result.APICallsInBlock) != 1 {
		t.Errorf("normalizeBasicBlock() has %d API calls, expected 1", len(result.APICallsInBlock))
	}
}

func TestSemanticAnalyzer_AnalyzeCFGSemantics_Integration(t *testing.T) {
	analyzer := NewSemanticAnalyzer()
	
	// Create a test CFG
	cfg := &opb.ControlFlowGraph{
		BasicBlocks: []*opb.BasicBlock{
			{
				Id:           "block_0",
				StartAddress: "0x1000",
				EndAddress:   "0x1002",
				Instructions: []*opb.Instruction{
					{Address: "0x1000", Opcode: "PUSH", Operands: "rbp"},
					{Address: "0x1001", Opcode: "MOV", Operands: "rbp, rsp"},
					{Address: "0x1002", Opcode: "XOR", Operands: "rax, rax"},
				},
			},
			{
				Id:           "block_1", 
				StartAddress: "0x1003",
				EndAddress:   "0x1003",
				Instructions: []*opb.Instruction{
					{Address: "0x1003", Opcode: "RET", Operands: ""},
				},
			},
		},
		Edges: []*opb.ControlFlowEdge{
			{
				From: "block_0",
				To:   "block_1",
				Type: opb.EdgeType_EDGE_TYPE_FALL_THROUGH,
			},
		},
	}
	
	result := analyzer.AnalyzeCFGSemantics(cfg)
	
	if result == nil {
		t.Fatal("AnalyzeCFGSemantics() returned nil")
	}
	
	// Check normalized blocks
	if len(result.NormalizedBlocks) != 2 {
		t.Errorf("AnalyzeCFGSemantics() returned %d normalized blocks, expected 2", 
			len(result.NormalizedBlocks))
	}
	
	// Check structural hash
	if result.StructuralHash == "" {
		t.Error("AnalyzeCFGSemantics().StructuralHash is empty")
	}
	
	// Check loop count
	if result.LoopCount < 0 {
		t.Errorf("AnalyzeCFGSemantics().LoopCount = %d, expected >= 0", result.LoopCount)
	}
	
	// Check branching factor
	if result.BranchingFactor < 0 {
		t.Errorf("AnalyzeCFGSemantics().BranchingFactor = %f, expected >= 0", result.BranchingFactor)
	}
	
	// Check that semantic patterns are populated
	if len(result.SemanticPatterns) == 0 {
		t.Error("AnalyzeCFGSemantics().SemanticPatterns is empty")
	}
}

func TestSemanticAnalyzer_computeStructuralHash(t *testing.T) {
	analyzer := NewSemanticAnalyzer()
	
	cfg1 := &opb.ControlFlowGraph{
		BasicBlocks: []*opb.BasicBlock{
			{
				Id: "block_0",
				Instructions: []*opb.Instruction{
					{Opcode: "PUSH", Operands: "rbp"},
					{Opcode: "MOV", Operands: "rbp, rsp"},
				},
			},
		},
		Edges: []*opb.ControlFlowEdge{
			{Type: opb.EdgeType_EDGE_TYPE_FALL_THROUGH},
		},
	}
	
	cfg2 := &opb.ControlFlowGraph{
		BasicBlocks: []*opb.BasicBlock{
			{
				Id: "different_block_id", // Different ID but same content
				Instructions: []*opb.Instruction{
					{Opcode: "PUSH", Operands: "rbp"},
					{Opcode: "MOV", Operands: "rbp, rsp"},
				},
			},
		},
		Edges: []*opb.ControlFlowEdge{
			{Type: opb.EdgeType_EDGE_TYPE_FALL_THROUGH},
		},
	}
	
	hash1 := analyzer.computeStructuralHash(cfg1)
	hash2 := analyzer.computeStructuralHash(cfg2)
	
	// Hashes should be the same despite different block IDs (structural similarity)
	if hash1 != hash2 {
		t.Errorf("computeStructuralHash() produced different hashes for structurally similar CFGs: %s vs %s", 
			hash1, hash2)
	}
	
	// Hash should not be empty
	if hash1 == "" {
		t.Error("computeStructuralHash() returned empty hash")
	}
}

func TestSemanticAnalyzer_countLoops(t *testing.T) {
	analyzer := NewSemanticAnalyzer()
	
	tests := []struct {
		name         string
		cfg          *opb.ControlFlowGraph
		expectedLoop int
	}{
		{
			name: "No loops",
			cfg: &opb.ControlFlowGraph{
				BasicBlocks: []*opb.BasicBlock{
					{Id: "block_0", StartAddress: "0x1000"},
					{Id: "block_1", StartAddress: "0x1010"},
				},
				Edges: []*opb.ControlFlowEdge{
					{From: "block_0", To: "block_1"},
				},
			},
			expectedLoop: 0,
		},
		{
			name: "Simple loop",
			cfg: &opb.ControlFlowGraph{
				BasicBlocks: []*opb.BasicBlock{
					{Id: "block_0", StartAddress: "0x1000"},
					{Id: "block_1", StartAddress: "0x1010"},
				},
				Edges: []*opb.ControlFlowEdge{
					{From: "block_0", To: "block_1"},
					{From: "block_1", To: "block_0"}, // Back edge
				},
			},
			expectedLoop: 1,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.countLoops(tt.cfg)
			if result != tt.expectedLoop {
				t.Errorf("countLoops() = %d, expected %d", result, tt.expectedLoop)
			}
		})
	}
}

func TestSemanticAnalyzer_computeBranchingFactor(t *testing.T) {
	analyzer := NewSemanticAnalyzer()
	
	tests := []struct {
		name           string
		cfg            *opb.ControlFlowGraph
		expectedFactor float64
	}{
		{
			name: "Empty CFG",
			cfg: &opb.ControlFlowGraph{
				BasicBlocks: []*opb.BasicBlock{},
			},
			expectedFactor: 0.0,
		},
		{
			name: "Single block no successors",
			cfg: &opb.ControlFlowGraph{
				BasicBlocks: []*opb.BasicBlock{
					{Id: "block_0", Successors: []string{}},
				},
			},
			expectedFactor: 0.0,
		},
		{
			name: "Linear CFG", 
			cfg: &opb.ControlFlowGraph{
				BasicBlocks: []*opb.BasicBlock{
					{Id: "block_0", Successors: []string{"block_1"}},
					{Id: "block_1", Successors: []string{}},
				},
			},
			expectedFactor: 0.5, // 1 successor total / 2 blocks
		},
		{
			name: "Branching CFG",
			cfg: &opb.ControlFlowGraph{
				BasicBlocks: []*opb.BasicBlock{
					{Id: "block_0", Successors: []string{"block_1", "block_2"}},
					{Id: "block_1", Successors: []string{"block_3"}},
					{Id: "block_2", Successors: []string{"block_3"}},
					{Id: "block_3", Successors: []string{}},
				},
			},
			expectedFactor: 1.0, // 4 successors total / 4 blocks
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.computeBranchingFactor(tt.cfg)
			if result != tt.expectedFactor {
				t.Errorf("computeBranchingFactor() = %f, expected %f", result, tt.expectedFactor)
			}
		})
	}
}

// Test helper functions for instruction classification
func TestInstructionClassificationHelpers(t *testing.T) {
	tests := []struct {
		name     string
		function func(string) bool
		testCases map[string]bool
	}{
		{
			name:     "isArithmeticOp",
			function: isArithmeticOp,
			testCases: map[string]bool{
				"ADD":    true,
				"SUB":    true,
				"MUL":    true,
				"DIV":    true,
				"MOV":    false,
				"JMP":    false,
				"PUSH":   false,
			},
		},
		{
			name:     "isMemoryOp",
			function: isMemoryOp,
			testCases: map[string]bool{
				"MOV":    true,
				"LEA":    true,
				"LDS":    true,
				"ADD":    false,
				"JMP":    false,
				"PUSH":   false,
			},
		},
		{
			name:     "isControlFlowOp",
			function: isControlFlowOp,
			testCases: map[string]bool{
				"JMP":    true,
				"JE":     true,
				"CALL":   true,
				"RET":    true,
				"MOV":    false,
				"ADD":    false,
			},
		},
		{
			name:     "isConditionalOp",
			function: isConditionalOp,
			testCases: map[string]bool{
				"JE":     true,
				"JNE":    true,
				"JA":     true,
				"JMP":    false,
				"CALL":   false,
				"RET":    false,
			},
		},
		{
			name:     "isStackOp",
			function: isStackOp,
			testCases: map[string]bool{
				"PUSH":   true,
				"POP":    true,
				"PUSHF":  true,
				"POPF":   true,
				"MOV":    false,
				"ADD":    false,
			},
		},
		{
			name:     "isBitwiseOp",
			function: isBitwiseOp,
			testCases: map[string]bool{
				"AND":    true,
				"OR":     true,
				"XOR":    true,
				"SHL":    true,
				"ADD":    false,
				"MOV":    false,
			},
		},
		{
			name:     "isFloatingPointOp",
			function: isFloatingPointOp,
			testCases: map[string]bool{
				"FADD":   true,
				"FSUB":   true,
				"FMUL":   true,
				"FLD":    true,
				"ADD":    false,
				"MOV":    false,
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for opcode, expected := range tt.testCases {
				result := tt.function(opcode)
				if result != expected {
					t.Errorf("%s(%s) = %v, expected %v", tt.name, opcode, result, expected)
				}
			}
		})
	}
}

func TestIsCryptoPattern(t *testing.T) {
	tests := []struct {
		operands string
		expected bool
	}{
		{"aes_encrypt", true},
		{"sha256_hash", true},
		{"md5_digest", true},
		{"rsa_key", true},
		{"des_cipher", true},
		{"crypto_func", true},
		{"hash_table", true},
		{"cipher_text", true},
		{"normal_operand", false},
		{"rax, rbx", false},
		{"[rbp+8]", false},
		{"0x1000", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.operands, func(t *testing.T) {
			result := isCryptoPattern(tt.operands)
			if result != tt.expected {
				t.Errorf("isCryptoPattern(%s) = %v, expected %v", tt.operands, result, tt.expected)
			}
		})
	}
}

func TestIsAPICall(t *testing.T) {
	tests := []struct {
		opcode   string
		operands string
		expected bool
	}{
		{"CALL", "malloc@plt", true},
		{"CALL", "printf@libc", true},
		{"CALL", "function@library", true},
		{"CALL", "0x1000", false},
		{"CALL", "rax", false},
		{"MOV", "malloc@plt", false},
		{"JMP", "function@library", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.opcode+"_"+tt.operands, func(t *testing.T) {
			result := isAPICall(tt.opcode, tt.operands)
			if result != tt.expected {
				t.Errorf("isAPICall(%s, %s) = %v, expected %v", 
					tt.opcode, tt.operands, result, tt.expected)
			}
		})
	}
}

func TestExtractAPIName(t *testing.T) {
	tests := []struct {
		operands string
		expected string
	}{
		{"malloc@plt", "plt"},
		{"printf@libc", "libc"},
		{"function@library", "library"},
		{"complex@lib.so.1", "lib.so.1"},
		{"no_at_symbol", ""},
		{"multiple@at@symbols", "at@symbols"},
		{"", ""},
	}
	
	for _, tt := range tests {
		t.Run(tt.operands, func(t *testing.T) {
			result := extractAPIName(tt.operands)
			if result != tt.expected {
				t.Errorf("extractAPIName(%s) = %s, expected %s", 
					tt.operands, result, tt.expected)
			}
		})
	}
}

func TestSemanticAnalyzer_EmptyCFG(t *testing.T) {
	analyzer := NewSemanticAnalyzer()
	
	cfg := &opb.ControlFlowGraph{
		BasicBlocks: []*opb.BasicBlock{},
		Edges:       []*opb.ControlFlowEdge{},
		Functions:   []*opb.Function{},
	}
	
	result := analyzer.AnalyzeCFGSemantics(cfg)
	
	if result == nil {
		t.Fatal("AnalyzeCFGSemantics() returned nil for empty CFG")
	}
	
	if len(result.NormalizedBlocks) != 0 {
		t.Errorf("AnalyzeCFGSemantics() returned %d normalized blocks for empty CFG, expected 0", 
			len(result.NormalizedBlocks))
	}
	
	if result.StructuralHash == "" {
		t.Error("AnalyzeCFGSemantics().StructuralHash is empty for empty CFG")
	}
	
	if result.LoopCount != 0 {
		t.Errorf("AnalyzeCFGSemantics().LoopCount = %d for empty CFG, expected 0", result.LoopCount)
	}
	
	if result.BranchingFactor != 0.0 {
		t.Errorf("AnalyzeCFGSemantics().BranchingFactor = %f for empty CFG, expected 0.0", result.BranchingFactor)
	}
}