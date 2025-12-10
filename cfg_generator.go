package main

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	opb "github.com/appsworld/katalinaware/protos"
	"golang.org/x/arch/x86/x86asm"
)

type CFGBuilder struct {
	instructions     []*InstructionInfo
	basicBlocks      map[string]*BasicBlockInfo
	functions        map[string]*FunctionInfo
	edges            []*EdgeInfo
	addressToBlock   map[uint64]string
	addressToInst    map[uint64]*InstructionInfo  // Performance optimization
}

type InstructionInfo struct {
	Address    uint64
	Inst       x86asm.Inst
	RawBytes   []byte
	IsLeader   bool
	BlockID    string
	FunctionID string
}

type BasicBlockInfo struct {
	ID              string
	StartAddr       uint64
	EndAddr         uint64
	Instructions    []*InstructionInfo
	Successors      []string
	Predecessors    []string
	FunctionID      string
	successorSet    map[string]bool  // Performance optimization
	predecessorSet  map[string]bool  // Performance optimization
}

type FunctionInfo struct {
	ID         string
	Name       string
	StartAddr  uint64
	EndAddr    uint64
	BlockIDs   []string
	InstCount  int
}

type EdgeInfo struct {
	From string
	To   string
	Type opb.EdgeType
}

// NewCFGBuilder creates a new CFG builder with initialized data structures.
// Sets up maps for optimized address-to-instruction and address-to-block lookups.
func NewCFGBuilder() *CFGBuilder {
	return &CFGBuilder{
		basicBlocks:    make(map[string]*BasicBlockInfo),
		functions:      make(map[string]*FunctionInfo),
		addressToBlock: make(map[uint64]string),
		addressToInst:  make(map[uint64]*InstructionInfo),
	}
}

func (cfg *CFGBuilder) GenerateCFG(f *MachoReader) (*opb.ControlFlowGraph, error) {
	instructions, err := cfg.disassembleTextSection(f)
	if err != nil {
		return nil, fmt.Errorf("failed to disassemble: %v", err)
	}
	
	cfg.instructions = instructions
	cfg.buildAddressIndex()  // Build performance index
	cfg.identifyLeaders()
	cfg.createBasicBlocks()
	cfg.identifyFunctions()
	cfg.buildEdges()
	
	return cfg.toProtobuf(), nil
}

// disassembleTextSection extracts and disassembles all instructions from __text sections.
// Pre-allocates instruction slice based on estimated count for better performance.
func (cfg *CFGBuilder) disassembleTextSection(f *MachoReader) ([]*InstructionInfo, error) {
	var totalTextSize uint64
	for _, sec := range f.MachoReader.Sections {
		if sec.Name == "__text" {
			totalTextSize += sec.SectionHeader.Size
		}
	}
	estimatedInsts := int(totalTextSize / 3)
	instructions := make([]*InstructionInfo, 0, estimatedInsts)
	
	for _, sec := range f.MachoReader.Sections {
		if sec.Name != "__text" {
			continue
		}
		
		startAddr := sec.SectionHeader.Addr
		endAddr := startAddr + sec.SectionHeader.Size
		code, err := sec.Data()
		if err != nil {
			return nil, err
		}
		
		currentAddr := startAddr
		for len(code) > 0 && currentAddr < endAddr {
			inst, err := x86asm.Decode(code, 64)
			if err != nil {
				code = code[1:]
				currentAddr++
				continue
			}
			
			if inst.Len == 0 {
				code = code[1:]
				currentAddr++
				continue
			}
			
			rawBytes := make([]byte, inst.Len)
			copy(rawBytes, code[:inst.Len])
			
			instInfo := &InstructionInfo{
				Address:  currentAddr,
				Inst:     inst,
				RawBytes: rawBytes,
			}
			
			instructions = append(instructions, instInfo)
			currentAddr += uint64(inst.Len)
			code = code[inst.Len:]
		}
	}
	
	return instructions, nil
}

// buildAddressIndex creates an address-to-instruction map for O(1) lookups during CFG construction.
func (cfg *CFGBuilder) buildAddressIndex() {
	for _, inst := range cfg.instructions {
		cfg.addressToInst[inst.Address] = inst
	}
}

func (cfg *CFGBuilder) identifyLeaders() {
	if len(cfg.instructions) == 0 {
		return
	}
	
	cfg.instructions[0].IsLeader = true
	
	for i, inst := range cfg.instructions {
		op := inst.Inst.Op
		
		switch op {
		case x86asm.JMP, x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JE, x86asm.JG, 
			 x86asm.JGE, x86asm.JL, x86asm.JLE, x86asm.JNE, x86asm.JNO, x86asm.JNP, x86asm.JNS, 
			 x86asm.JO, x86asm.JP, x86asm.JS, x86asm.CALL:
			
			if target := cfg.getJumpTarget(inst); target != 0 {
				cfg.markLeaderAtAddress(target)
			}
			
			if i+1 < len(cfg.instructions) && op != x86asm.JMP {
				cfg.instructions[i+1].IsLeader = true
			}
			
		case x86asm.RET:
			if i+1 < len(cfg.instructions) {
				cfg.instructions[i+1].IsLeader = true
			}
		}
	}
}

func (cfg *CFGBuilder) getJumpTarget(inst *InstructionInfo) uint64 {
	if len(inst.Inst.Args) == 0 {
		return 0
	}
	
	arg := inst.Inst.Args[0]
	switch arg := arg.(type) {
	case x86asm.Rel:
		return inst.Address + uint64(inst.Inst.Len) + uint64(arg)
	case x86asm.Imm:
		return uint64(arg)
	}
	
	return 0
}

func (cfg *CFGBuilder) markLeaderAtAddress(addr uint64) {
	if inst := cfg.addressToInst[addr]; inst != nil {
		inst.IsLeader = true
	}
}

// createBasicBlocks groups instructions into basic blocks based on identified leaders.
// Pre-allocates data structures based on leader count for optimal performance.
func (cfg *CFGBuilder) createBasicBlocks() {
	if len(cfg.instructions) == 0 {
		return
	}
	
	leaderCount := 0
	for _, inst := range cfg.instructions {
		if inst.IsLeader {
			leaderCount++
		}
	}
	
	cfg.basicBlocks = make(map[string]*BasicBlockInfo, leaderCount)
	cfg.addressToBlock = make(map[uint64]string, leaderCount)
	
	var currentBlock *BasicBlockInfo
	blockCounter := 0
	
	for _, inst := range cfg.instructions {
		if inst.IsLeader || currentBlock == nil {
			if currentBlock != nil {
				currentBlock.EndAddr = currentBlock.Instructions[len(currentBlock.Instructions)-1].Address
				cfg.basicBlocks[currentBlock.ID] = currentBlock
			}
			
			blockID := fmt.Sprintf("bb_%d", blockCounter)
			blockCounter++
			
			currentBlock = &BasicBlockInfo{
				ID:           blockID,
				StartAddr:    inst.Address,
				Instructions: make([]*InstructionInfo, 0, 8),
				Successors:   make([]string, 0, 2),
				Predecessors: make([]string, 0, 2),
			}
			
			cfg.addressToBlock[inst.Address] = blockID
		}
		
		inst.BlockID = currentBlock.ID
		currentBlock.Instructions = append(currentBlock.Instructions, inst)
	}
	
	if currentBlock != nil {
		currentBlock.EndAddr = currentBlock.Instructions[len(currentBlock.Instructions)-1].Address
		cfg.basicBlocks[currentBlock.ID] = currentBlock
	}
}

func (cfg *CFGBuilder) identifyFunctions() {
	functionStarts := make(map[uint64]bool)
	if len(cfg.instructions) > 0 {
		functionStarts[cfg.instructions[0].Address] = true
	}
	
	// Find function starts from CALL targets
	for _, inst := range cfg.instructions {
		if inst.Inst.Op == x86asm.CALL {
			if target := cfg.getJumpTarget(inst); target != 0 {
				functionStarts[target] = true
			}
		}
	}
	
	var sortedStarts []uint64
	for addr := range functionStarts {
		sortedStarts = append(sortedStarts, addr)
	}
	sort.Slice(sortedStarts, func(i, j int) bool {
		return sortedStarts[i] < sortedStarts[j]
	})
	
	cfg.assignFunctionsOptimized(sortedStarts)
}

// assignFunctionsOptimized assigns instructions and blocks to functions using binary search 
// for O(n log m) complexity instead of O(n*m) where n=instructions, m=functions.
func (cfg *CFGBuilder) assignFunctionsOptimized(sortedStarts []uint64) {
	cfg.functions = make(map[string]*FunctionInfo, len(sortedStarts))
	
	functions := make([]*FunctionInfo, len(sortedStarts))
	for i, startAddr := range sortedStarts {
		funcID := fmt.Sprintf("func_%d", i)
		endAddr := uint64(0)
		if i+1 < len(sortedStarts) {
			endAddr = sortedStarts[i+1] - 1
		} else {
			endAddr = cfg.instructions[len(cfg.instructions)-1].Address
		}
		
		functions[i] = &FunctionInfo{
			ID:        funcID,
			Name:      fmt.Sprintf("sub_%x", startAddr),
			StartAddr: startAddr,
			EndAddr:   endAddr,
			BlockIDs:  make([]string, 0, 10),
		}
		cfg.functions[funcID] = functions[i]
	}
	
	blockIDSets := make([]map[string]bool, len(functions))
	for i := range blockIDSets {
		blockIDSets[i] = make(map[string]bool)
	}
	
	for _, inst := range cfg.instructions {
		funcIdx := cfg.findFunctionIndex(sortedStarts, inst.Address)
		if funcIdx >= 0 && funcIdx < len(functions) {
			function := functions[funcIdx]
			inst.FunctionID = function.ID
			function.InstCount++
			
			if block := cfg.basicBlocks[inst.BlockID]; block != nil {
				block.FunctionID = function.ID
				if !blockIDSets[funcIdx][inst.BlockID] {
					blockIDSets[funcIdx][inst.BlockID] = true
					function.BlockIDs = append(function.BlockIDs, inst.BlockID)
				}
			}
		}
	}
}

// findFunctionIndex uses binary search to locate which function contains the given address.
// Returns -1 if the address is not within any function's range.
func (cfg *CFGBuilder) findFunctionIndex(sortedStarts []uint64, addr uint64) int {
	left, right := 0, len(sortedStarts)-1
	result := -1
	
	for left <= right {
		mid := (left + right) / 2
		if sortedStarts[mid] <= addr {
			result = mid
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	
	if result >= 0 && result < len(sortedStarts) {
		endAddr := uint64(0)
		if result+1 < len(sortedStarts) {
			endAddr = sortedStarts[result+1] - 1
		} else {
			endAddr = cfg.instructions[len(cfg.instructions)-1].Address
		}
		if addr <= endAddr {
			return result
		}
	}
	
	return -1
}

func (cfg *CFGBuilder) buildEdges() {
	for _, block := range cfg.basicBlocks {
		if len(block.Instructions) == 0 {
			continue
		}
		
		lastInst := block.Instructions[len(block.Instructions)-1]
		op := lastInst.Inst.Op
		
		switch op {
		case x86asm.JMP:
			if target := cfg.getJumpTarget(lastInst); target != 0 {
				if targetBlockID := cfg.addressToBlock[target]; targetBlockID != "" {
					cfg.addEdge(block.ID, targetBlockID, opb.EdgeType_EDGE_TYPE_UNCONDITIONAL_JUMP)
				}
			}
			
		case x86asm.JA, x86asm.JAE, x86asm.JB, x86asm.JBE, x86asm.JE, x86asm.JG, 
			 x86asm.JGE, x86asm.JL, x86asm.JLE, x86asm.JNE, x86asm.JNO, x86asm.JNP, 
			 x86asm.JNS, x86asm.JO, x86asm.JP, x86asm.JS:
			
			if target := cfg.getJumpTarget(lastInst); target != 0 {
				if targetBlockID := cfg.addressToBlock[target]; targetBlockID != "" {
					cfg.addEdge(block.ID, targetBlockID, opb.EdgeType_EDGE_TYPE_CONDITIONAL_JUMP)
				}
			}
			
			if nextBlock := cfg.getNextBlock(block); nextBlock != "" {
				cfg.addEdge(block.ID, nextBlock, opb.EdgeType_EDGE_TYPE_FALL_THROUGH)
			}
			
		case x86asm.CALL:
			if target := cfg.getJumpTarget(lastInst); target != 0 {
				if targetBlockID := cfg.addressToBlock[target]; targetBlockID != "" {
					cfg.addEdge(block.ID, targetBlockID, opb.EdgeType_EDGE_TYPE_CALL)
				}
			}
			
			if nextBlock := cfg.getNextBlock(block); nextBlock != "" {
				cfg.addEdge(block.ID, nextBlock, opb.EdgeType_EDGE_TYPE_FALL_THROUGH)
			}
			
		case x86asm.RET:
			
		default:
			if nextBlock := cfg.getNextBlock(block); nextBlock != "" {
				cfg.addEdge(block.ID, nextBlock, opb.EdgeType_EDGE_TYPE_FALL_THROUGH)
			}
		}
	}
}

func (cfg *CFGBuilder) getNextBlock(block *BasicBlockInfo) string {
	if len(block.Instructions) == 0 {
		return ""
	}
	
	lastInst := block.Instructions[len(block.Instructions)-1]
	nextAddr := lastInst.Address + uint64(lastInst.Inst.Len)
	
	return cfg.addressToBlock[nextAddr]
}

// addEdge creates a control flow edge and updates successor/predecessor relationships.
// Uses map-based tracking to avoid O(n) duplicate checks for better performance.
func (cfg *CFGBuilder) addEdge(from, to string, edgeType opb.EdgeType) {
	edge := &EdgeInfo{
		From: from,
		To:   to,
		Type: edgeType,
	}
	cfg.edges = append(cfg.edges, edge)
	
	if fromBlock := cfg.basicBlocks[from]; fromBlock != nil {
		if fromBlock.successorSet == nil {
			fromBlock.successorSet = make(map[string]bool)
			for _, succ := range fromBlock.Successors {
				fromBlock.successorSet[succ] = true
			}
		}
		if !fromBlock.successorSet[to] {
			fromBlock.successorSet[to] = true
			fromBlock.Successors = append(fromBlock.Successors, to)
		}
	}
	
	if toBlock := cfg.basicBlocks[to]; toBlock != nil {
		if toBlock.predecessorSet == nil {
			toBlock.predecessorSet = make(map[string]bool)
			for _, pred := range toBlock.Predecessors {
				toBlock.predecessorSet[pred] = true
			}
		}
		if !toBlock.predecessorSet[from] {
			toBlock.predecessorSet[from] = true
			toBlock.Predecessors = append(toBlock.Predecessors, from)
		}
	}
}

// toProtobuf converts the internal CFG representation to protobuf format.
// Pre-allocates slices and reuses buffers for optimal memory usage and performance.
func (cfg *CFGBuilder) toProtobuf() *opb.ControlFlowGraph {
	cfgPb := &opb.ControlFlowGraph{
		BasicBlocks: make([]*opb.BasicBlock, 0, len(cfg.basicBlocks)),
		Functions:   make([]*opb.Function, 0, len(cfg.functions)),
		Edges:       make([]*opb.ControlFlowEdge, 0, len(cfg.edges)),
	}
	
	hexBuf := make([]byte, 0, 32)
	
	for _, block := range cfg.basicBlocks {
		blockPb := &opb.BasicBlock{
			Id:           block.ID,
			StartAddress: cfg.formatAddressOptimized(block.StartAddr),
			EndAddress:   cfg.formatAddressOptimized(block.EndAddr),
			Successors:   block.Successors,
			Predecessors: block.Predecessors,
			FunctionId:   block.FunctionID,
			Instructions: make([]*opb.Instruction, 0, len(block.Instructions)),
		}
		
		for _, inst := range block.Instructions {
			hexBuf = hexBuf[:0]
			hexBuf = hex.AppendEncode(hexBuf, inst.RawBytes)
			
			instPb := &opb.Instruction{
				Address:  cfg.formatAddressOptimized(inst.Address),
				Opcode:   inst.Inst.Op.String(),
				Operands: cfg.formatOperands(inst.Inst),
				RawBytes: string(hexBuf),
			}
			blockPb.Instructions = append(blockPb.Instructions, instPb)
		}
		
		cfgPb.BasicBlocks = append(cfgPb.BasicBlocks, blockPb)
	}
	
	for _, function := range cfg.functions {
		funcPb := &opb.Function{
			Id:               function.ID,
			Name:             function.Name,
			StartAddress:     cfg.formatAddressOptimized(function.StartAddr),
			EndAddress:       cfg.formatAddressOptimized(function.EndAddr),
			BasicBlockIds:    function.BlockIDs,
			InstructionCount: int32(function.InstCount),
		}
		cfgPb.Functions = append(cfgPb.Functions, funcPb)
	}
	
	for _, edge := range cfg.edges {
		edgePb := &opb.ControlFlowEdge{
			From: edge.From,
			To:   edge.To,
			Type: edge.Type,
		}
		cfgPb.Edges = append(cfgPb.Edges, edgePb)
	}
	
	return cfgPb
}

// formatAddressOptimized formats addresses using strconv instead of fmt.Sprintf for better performance.
func (cfg *CFGBuilder) formatAddressOptimized(addr uint64) string {
	return "0x" + strconv.FormatUint(addr, 16)
}

func (cfg *CFGBuilder) formatOperands(inst x86asm.Inst) string {
	var operands []string
	for _, arg := range inst.Args {
		if arg != nil {
			operands = append(operands, arg.String())
		}
	}
	return strings.Join(operands, ", ")
}

// contains checks if a string slice contains a specific item.
// Returns true if the item is found, false otherwise.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
