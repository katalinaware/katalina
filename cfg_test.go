package main

import (
	"fmt"
	"testing"

	opb "github.com/appsworld/katalinaware/protos"
)

func TestNewCFGBuilder(t *testing.T) {
	builder := NewCFGBuilder()
	
	if builder == nil {
		t.Fatal("NewCFGBuilder() returned nil")
	}
	
	if builder.basicBlocks == nil {
		t.Error("NewCFGBuilder() did not initialize basicBlocks")
	}
	
	if builder.functions == nil {
		t.Error("NewCFGBuilder() did not initialize functions")
	}
	
	if builder.addressToBlock == nil {
		t.Error("NewCFGBuilder() did not initialize addressToBlock")
	}
}

// Test basic CFG structure with real protobuf types
func TestCFGProtobufStructure(t *testing.T) {
	// Test that we can create the basic CFG protobuf structures
	cfg := &opb.ControlFlowGraph{
		BasicBlocks: []*opb.BasicBlock{
			{
				Id:           "block_0",
				StartAddress: "0x1000",
				EndAddress:   "0x1010",
				Instructions: []*opb.Instruction{
					{
						Address:  "0x1000",
						Opcode:   "PUSH",
						Operands: "rbp",
						RawBytes: "55",
					},
					{
						Address:  "0x1001",
						Opcode:   "MOV",
						Operands: "rbp, rsp",
						RawBytes: "4889e5",
					},
				},
				Successors:   []string{"block_1"},
				Predecessors: []string{},
				FunctionId:   "func_0",
			},
		},
		Edges: []*opb.ControlFlowEdge{
			{
				From: "block_0",
				To:   "block_1",
				Type: opb.EdgeType_EDGE_TYPE_FALL_THROUGH,
			},
		},
		Functions: []*opb.Function{
			{
				Id:             "func_0",
				Name:           "test_function",
				StartAddress:   "0x1000",
				EndAddress:     "0x1020",
				BasicBlockIds:  []string{"block_0", "block_1"},
				InstructionCount: 5,
			},
		},
	}
	
	// Verify basic structure
	if len(cfg.BasicBlocks) != 1 {
		t.Errorf("CFG has %d basic blocks, expected 1", len(cfg.BasicBlocks))
	}
	
	if len(cfg.Edges) != 1 {
		t.Errorf("CFG has %d edges, expected 1", len(cfg.Edges))
	}
	
	if len(cfg.Functions) != 1 {
		t.Errorf("CFG has %d functions, expected 1", len(cfg.Functions))
	}
	
	// Verify basic block structure
	block := cfg.BasicBlocks[0]
	if block.Id != "block_0" {
		t.Errorf("Block ID = %s, expected block_0", block.Id)
	}
	
	if len(block.Instructions) != 2 {
		t.Errorf("Block has %d instructions, expected 2", len(block.Instructions))
	}
	
	// Verify instruction structure
	inst := block.Instructions[0]
	if inst.Opcode != "PUSH" {
		t.Errorf("Instruction opcode = %s, expected PUSH", inst.Opcode)
	}
	
	if inst.Address != "0x1000" {
		t.Errorf("Instruction address = %s, expected 0x1000", inst.Address)
	}
}

func TestCFGEdgeTypes(t *testing.T) {
	tests := []struct {
		name     string
		edgeType opb.EdgeType
		expected string
	}{
		{"Fall through", opb.EdgeType_EDGE_TYPE_FALL_THROUGH, "EDGE_TYPE_FALL_THROUGH"},
		{"Conditional jump", opb.EdgeType_EDGE_TYPE_CONDITIONAL_JUMP, "EDGE_TYPE_CONDITIONAL_JUMP"},
		{"Unconditional jump", opb.EdgeType_EDGE_TYPE_UNCONDITIONAL_JUMP, "EDGE_TYPE_UNCONDITIONAL_JUMP"},
		{"Call", opb.EdgeType_EDGE_TYPE_CALL, "EDGE_TYPE_CALL"},
		{"Return", opb.EdgeType_EDGE_TYPE_RETURN, "EDGE_TYPE_RETURN"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.edgeType.String() != tt.expected {
				t.Errorf("EdgeType.String() = %s, expected %s", tt.edgeType.String(), tt.expected)
			}
		})
	}
}

func TestInstructionStructure(t *testing.T) {
	inst := &opb.Instruction{
		Address:  "0x1000",
		Opcode:   "MOV",
		Operands: "rax, rbx",
		RawBytes: "4889d8",
	}
	
	if inst.Address != "0x1000" {
		t.Errorf("Instruction address = %s, expected 0x1000", inst.Address)
	}
	
	if inst.Opcode != "MOV" {
		t.Errorf("Instruction opcode = %s, expected MOV", inst.Opcode)
	}
	
	if inst.Operands != "rax, rbx" {
		t.Errorf("Instruction operands = %s, expected 'rax, rbx'", inst.Operands)
	}
	
	if inst.RawBytes != "4889d8" {
		t.Errorf("Instruction raw_bytes = %s, expected 4889d8", inst.RawBytes)
	}
}

func TestFunctionStructure(t *testing.T) {
	function := &opb.Function{
		Id:             "func_0",
		Name:           "main",
		StartAddress:   "0x1000",
		EndAddress:     "0x1100",
		BasicBlockIds:  []string{"block_0", "block_1", "block_2"},
		InstructionCount: 25,
	}
	
	if function.Id != "func_0" {
		t.Errorf("Function ID = %s, expected func_0", function.Id)
	}
	
	if function.Name != "main" {
		t.Errorf("Function name = %s, expected main", function.Name)
	}
	
	if len(function.BasicBlockIds) != 3 {
		t.Errorf("Function has %d basic blocks, expected 3", len(function.BasicBlockIds))
	}
	
	if function.InstructionCount != 25 {
		t.Errorf("Function instruction count = %d, expected 25", function.InstructionCount)
	}
}

// Test CFG Builder internal structures
func TestCFGBuilderTypes(t *testing.T) {
	// Test InstructionInfo
	instInfo := &InstructionInfo{
		Address:    0x1000,
		IsLeader:   true,
		BlockID:    "block_0",
		FunctionID: "func_0",
	}
	
	if instInfo.Address != 0x1000 {
		t.Errorf("InstructionInfo address = 0x%x, expected 0x1000", instInfo.Address)
	}
	
	if !instInfo.IsLeader {
		t.Error("InstructionInfo should be marked as leader")
	}
	
	// Test BasicBlockInfo
	blockInfo := &BasicBlockInfo{
		ID:           "block_0",
		StartAddr:    0x1000,
		EndAddr:      0x1010,
		Successors:   []string{"block_1"},
		Predecessors: []string{},
		FunctionID:   "func_0",
	}
	
	if blockInfo.ID != "block_0" {
		t.Errorf("BasicBlockInfo ID = %s, expected block_0", blockInfo.ID)
	}
	
	if len(blockInfo.Successors) != 1 {
		t.Errorf("BasicBlockInfo has %d successors, expected 1", len(blockInfo.Successors))
	}
	
	// Test FunctionInfo
	funcInfo := &FunctionInfo{
		ID:        "func_0",
		Name:      "test_function",
		StartAddr: 0x1000,
		EndAddr:   0x1100,
		BlockIDs:  []string{"block_0", "block_1"},
		InstCount: 10,
	}
	
	if funcInfo.ID != "func_0" {
		t.Errorf("FunctionInfo ID = %s, expected func_0", funcInfo.ID)
	}
	
	if len(funcInfo.BlockIDs) != 2 {
		t.Errorf("FunctionInfo has %d blocks, expected 2", len(funcInfo.BlockIDs))
	}
	
	// Test EdgeInfo
	edgeInfo := &EdgeInfo{
		From: "block_0",
		To:   "block_1",
		Type: opb.EdgeType_EDGE_TYPE_FALL_THROUGH,
	}
	
	if edgeInfo.From != "block_0" {
		t.Errorf("EdgeInfo from = %s, expected block_0", edgeInfo.From)
	}
	
	if edgeInfo.Type != opb.EdgeType_EDGE_TYPE_FALL_THROUGH {
		t.Errorf("EdgeInfo type = %v, expected EDGE_TYPE_FALL_THROUGH", edgeInfo.Type)
	}
}

// Integration test that would work with a real binary (disabled for now)
func TestCFGBuilderIntegration_Disabled(t *testing.T) {
	t.Skip("Integration test requires real binary - skipping for unit tests")
	
	// This would be the structure for integration testing:
	// 1. Load a test binary
	// 2. Create CFGBuilder
	// 3. Generate CFG
	// 4. Verify results
	
	/*
	builder := NewCFGBuilder()
	
	// Would need a real MachoReader here
	// cfg, err := builder.GenerateCFG(machoReader)
	// if err != nil {
	//     t.Fatalf("GenerateCFG() failed: %v", err)
	// }
	
	// Verify CFG structure
	// if len(cfg.BasicBlocks) == 0 {
	//     t.Error("CFG has no basic blocks")
	// }
	*/
}

// Test empty CFG creation
func TestEmptyCFG(t *testing.T) {
	cfg := &opb.ControlFlowGraph{
		BasicBlocks: []*opb.BasicBlock{},
		Edges:       []*opb.ControlFlowEdge{},
		Functions:   []*opb.Function{},
	}
	
	if len(cfg.BasicBlocks) != 0 {
		t.Errorf("Empty CFG has %d basic blocks, expected 0", len(cfg.BasicBlocks))
	}
	
	if len(cfg.Edges) != 0 {
		t.Errorf("Empty CFG has %d edges, expected 0", len(cfg.Edges))
	}
	
	if len(cfg.Functions) != 0 {
		t.Errorf("Empty CFG has %d functions, expected 0", len(cfg.Functions))
	}
}

// Test CFG builder address index performance
func TestCFGBuilder_AddressIndex(t *testing.T) {
	builder := NewCFGBuilder()
	
	// Create mock instructions
	instructions := []*InstructionInfo{
		{Address: 0x1000},
		{Address: 0x1010},
		{Address: 0x1020},
		{Address: 0x1030},
	}
	
	builder.instructions = instructions
	builder.buildAddressIndex()
	
	// Test O(1) lookup performance
	for _, inst := range instructions {
		found := builder.addressToInst[inst.Address]
		if found != inst {
			t.Errorf("Address index lookup failed for address 0x%x", inst.Address)
		}
	}
	
	// Test non-existent address
	if found := builder.addressToInst[0x9999]; found != nil {
		t.Error("Address index should return nil for non-existent address")
	}
}

// Test CFG builder function assignment optimization
func TestCFGBuilder_FunctionAssignmentOptimized(t *testing.T) {
	builder := NewCFGBuilder()
	
	// Create mock instructions spanning multiple functions
	instructions := []*InstructionInfo{
		{Address: 0x1000}, // func_0
		{Address: 0x1010}, // func_0
		{Address: 0x2000}, // func_1
		{Address: 0x2010}, // func_1
		{Address: 0x3000}, // func_2
	}
	
	builder.instructions = instructions
	builder.buildAddressIndex()
	
	// Mock basic blocks
	builder.basicBlocks = map[string]*BasicBlockInfo{
		"bb_0": {ID: "bb_0"},
		"bb_1": {ID: "bb_1"},
		"bb_2": {ID: "bb_2"},
	}
	
	// Assign block IDs to instructions
	instructions[0].BlockID = "bb_0"
	instructions[1].BlockID = "bb_0"
	instructions[2].BlockID = "bb_1"
	instructions[3].BlockID = "bb_1"
	instructions[4].BlockID = "bb_2"
	
	// Test optimized function assignment
	sortedStarts := []uint64{0x1000, 0x2000, 0x3000}
	builder.assignFunctionsOptimized(sortedStarts)
	
	// Verify function assignment
	if instructions[0].FunctionID != "func_0" {
		t.Errorf("Instruction at 0x1000 assigned to %s, expected func_0", instructions[0].FunctionID)
	}
	if instructions[2].FunctionID != "func_1" {
		t.Errorf("Instruction at 0x2000 assigned to %s, expected func_1", instructions[2].FunctionID)
	}
	if instructions[4].FunctionID != "func_2" {
		t.Errorf("Instruction at 0x3000 assigned to %s, expected func_2", instructions[4].FunctionID)
	}
	
	// Verify function count
	if len(builder.functions) != 3 {
		t.Errorf("Expected 3 functions, got %d", len(builder.functions))
	}
}

// Test CFG builder binary search function index
func TestCFGBuilder_FindFunctionIndex(t *testing.T) {
	builder := NewCFGBuilder()
	
	// Create mock instructions for testing range checking
	builder.instructions = []*InstructionInfo{
		{Address: 0x3000},
	}
	
	sortedStarts := []uint64{0x1000, 0x2000, 0x3000}
	
	tests := []struct {
		name     string
		address  uint64
		expected int
	}{
		{"First function", 0x1000, 0},
		{"Middle of first function", 0x1500, 0},
		{"Second function", 0x2000, 1},
		{"Third function", 0x3000, 2},
		{"Before any function", 0x500, -1},
		{"After last function", 0x4000, -1},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.findFunctionIndex(sortedStarts, tt.address)
			if result != tt.expected {
				t.Errorf("findFunctionIndex(0x%x) = %d, expected %d", tt.address, result, tt.expected)
			}
		})
	}
}

// Test CFG builder edge optimization with successor/predecessor sets
func TestCFGBuilder_EdgeOptimization(t *testing.T) {
	builder := NewCFGBuilder()
	
	// Create mock basic blocks
	builder.basicBlocks = map[string]*BasicBlockInfo{
		"bb_0": {
			ID:         "bb_0",
			Successors: []string{},
		},
		"bb_1": {
			ID:           "bb_1",
			Predecessors: []string{},
		},
	}
	
	// Add multiple edges to test deduplication
	builder.addEdge("bb_0", "bb_1", opb.EdgeType_EDGE_TYPE_FALL_THROUGH)
	builder.addEdge("bb_0", "bb_1", opb.EdgeType_EDGE_TYPE_FALL_THROUGH) // Duplicate
	
	fromBlock := builder.basicBlocks["bb_0"]
	toBlock := builder.basicBlocks["bb_1"]
	
	// Verify no duplicates in successor/predecessor lists
	if len(fromBlock.Successors) != 1 {
		t.Errorf("Expected 1 successor, got %d", len(fromBlock.Successors))
	}
	if len(toBlock.Predecessors) != 1 {
		t.Errorf("Expected 1 predecessor, got %d", len(toBlock.Predecessors))
	}
	
	// Verify edge count (duplicates should be added to edge list)
	if len(builder.edges) != 2 {
		t.Errorf("Expected 2 edges in edge list, got %d", len(builder.edges))
	}
}

// Benchmark CFG builder performance optimizations
func BenchmarkCFGBuilder_AddressIndexLookup(b *testing.B) {
	builder := NewCFGBuilder()
	
	// Create large number of instructions
	const numInsts = 10000
	instructions := make([]*InstructionInfo, numInsts)
	for i := 0; i < numInsts; i++ {
		instructions[i] = &InstructionInfo{
			Address: uint64(0x1000 + i*4),
		}
	}
	
	builder.instructions = instructions
	builder.buildAddressIndex()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Test O(1) lookup performance
		addr := uint64(0x1000 + (i%numInsts)*4)
		_ = builder.addressToInst[addr]
	}
}

func BenchmarkCFGBuilder_FunctionAssignment(b *testing.B) {
	builder := NewCFGBuilder()
	
	// Create realistic number of instructions and functions
	const numInsts = 50000
	const numFuncs = 1000
	
	instructions := make([]*InstructionInfo, numInsts)
	for i := 0; i < numInsts; i++ {
		instructions[i] = &InstructionInfo{
			Address: uint64(0x1000 + i*4),
			BlockID: fmt.Sprintf("bb_%d", i/10),
		}
	}
	
	// Create function starts
	sortedStarts := make([]uint64, numFuncs)
	for i := 0; i < numFuncs; i++ {
		sortedStarts[i] = uint64(0x1000 + (i*numInsts/numFuncs)*4)
	}
	
	builder.instructions = instructions
	builder.buildAddressIndex()
	
	// Create mock basic blocks
	builder.basicBlocks = make(map[string]*BasicBlockInfo)
	for i := 0; i < numInsts/10; i++ {
		builder.basicBlocks[fmt.Sprintf("bb_%d", i)] = &BasicBlockInfo{
			ID: fmt.Sprintf("bb_%d", i),
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset for each iteration
		for _, inst := range builder.instructions {
			inst.FunctionID = ""
		}
		builder.functions = make(map[string]*FunctionInfo)
		
		builder.assignFunctionsOptimized(sortedStarts)
	}
}

// Test CFG with multiple functions
func TestMultiFunctionCFG(t *testing.T) {
	cfg := &opb.ControlFlowGraph{
		BasicBlocks: []*opb.BasicBlock{
			{Id: "block_0", FunctionId: "func_0"},
			{Id: "block_1", FunctionId: "func_0"},
			{Id: "block_2", FunctionId: "func_1"},
		},
		Functions: []*opb.Function{
			{Id: "func_0", Name: "main", BasicBlockIds: []string{"block_0", "block_1"}},
			{Id: "func_1", Name: "helper", BasicBlockIds: []string{"block_2"}},
		},
	}
	
	// Count blocks per function
	func0Blocks := 0
	func1Blocks := 0
	
	for _, block := range cfg.BasicBlocks {
		switch block.FunctionId {
		case "func_0":
			func0Blocks++
		case "func_1":
			func1Blocks++
		}
	}
	
	if func0Blocks != 2 {
		t.Errorf("Function func_0 has %d blocks, expected 2", func0Blocks)
	}
	
	if func1Blocks != 1 {
		t.Errorf("Function func_1 has %d blocks, expected 1", func1Blocks)
	}
}