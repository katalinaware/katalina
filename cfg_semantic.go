package main

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	opb "github.com/appsworld/katalinaware/protos"
)

type SemanticCFG struct {
	StructuralHash     string
	LoopCount          int
	BranchingFactor    float64
	CallDepth          int
	SemanticPatterns   []string
	APICallSequences   []string
	DataFlowPatterns   []string
	NormalizedBlocks   []*NormalizedBasicBlock
	CFGEmbedding       []float64
}

type NormalizedBasicBlock struct {
	ID                string
	SemanticHash      string
	InstructionTypes  []string
	DataDependencies  []string
	ControlFlowType   string
	Successors        []string
	APICallsInBlock   []string
}

type InstructionSemantic struct {
	Category    string  // ARITHMETIC, MEMORY, CONTROL, CRYPTO, etc.
	Operation   string  // ADD, MOV, JMP, etc.
	Operands    int     // Number of operands
	IsCondition bool    // Is conditional instruction
	IsCrypto    bool    // Cryptographic operation
	IsAPI       bool    // API call
	Normalized  string  // Normalized representation
}

// NewSemanticAnalyzer creates a new semantic analyzer with initialized pattern maps.
// Pre-populates cryptographic and API call pattern dictionaries for fast lookup.
func NewSemanticAnalyzer() *SemanticAnalyzer {
	return &SemanticAnalyzer{
		cryptoPatterns: initCryptoPatterns(),
		apiPatterns:    initAPIPatterns(),
	}
}

type SemanticAnalyzer struct {
	cryptoPatterns map[string]bool
	apiPatterns    map[string]bool
}

func (sa *SemanticAnalyzer) AnalyzeCFGSemantics(cfg *opb.ControlFlowGraph) *SemanticCFG {
	semantic := &SemanticCFG{
		NormalizedBlocks: make([]*NormalizedBasicBlock, 0),
		SemanticPatterns: make([]string, 0),
		APICallSequences: make([]string, 0),
		DataFlowPatterns: make([]string, 0),
	}
	
	semantic.StructuralHash = sa.computeStructuralHash(cfg)
	semantic.LoopCount = sa.countLoops(cfg)
	semantic.BranchingFactor = sa.computeBranchingFactor(cfg)
	semantic.CallDepth = sa.computeCallDepth(cfg)
	
	for _, block := range cfg.BasicBlocks {
		normalizedBlock := sa.normalizeBasicBlock(block)
		semantic.NormalizedBlocks = append(semantic.NormalizedBlocks, normalizedBlock)
		
		// Extract semantic patterns from block
		patterns := sa.extractSemanticPatterns(block)
		semantic.SemanticPatterns = append(semantic.SemanticPatterns, patterns...)
		
		// Extract API call sequences
		apiCalls := sa.extractAPICallSequences(block)
		semantic.APICallSequences = append(semantic.APICallSequences, apiCalls...)
	}
	
	// Remove duplicates and sort for deterministic comparison
	semantic.SemanticPatterns = removeDuplicatesAndSort(semantic.SemanticPatterns)
	semantic.APICallSequences = removeDuplicatesAndSort(semantic.APICallSequences)
	semantic.DataFlowPatterns = sa.analyzeDataFlowPatterns(cfg)
	
	// Generate embedding vector for ML comparison
	semantic.CFGEmbedding = sa.generateCFGEmbedding(semantic)
	
	return semantic
}

func (sa *SemanticAnalyzer) normalizeBasicBlock(block *opb.BasicBlock) *NormalizedBasicBlock {
	normalized := &NormalizedBasicBlock{
		ID:               block.Id,
		InstructionTypes: make([]string, 0),
		DataDependencies: make([]string, 0),
		Successors:       block.Successors,
		APICallsInBlock:  make([]string, 0),
	}
	
	var semanticElements []string
	
	for _, inst := range block.Instructions {
		semantic := sa.classifyInstruction(inst)
		normalized.InstructionTypes = append(normalized.InstructionTypes, semantic.Category)
		semanticElements = append(semanticElements, semantic.Normalized)
		
		if semantic.IsAPI {
			normalized.APICallsInBlock = append(normalized.APICallsInBlock, semantic.Operation)
		}
	}
	
	// Create semantic hash based on instruction semantics, not addresses
	hashInput := strings.Join(semanticElements, "|")
	hash := sha256.Sum256([]byte(hashInput))
	normalized.SemanticHash = fmt.Sprintf("%x", hash)[:16]
	
	// Determine control flow type
	if len(block.Instructions) > 0 {
		lastInst := block.Instructions[len(block.Instructions)-1]
		normalized.ControlFlowType = sa.getControlFlowType(lastInst)
	}
	
	return normalized
}

func (sa *SemanticAnalyzer) classifyInstruction(inst *opb.Instruction) InstructionSemantic {
	opcode := strings.ToUpper(inst.Opcode)
	operandCount := len(strings.Split(inst.Operands, ","))
	if inst.Operands == "" {
		operandCount = 0
	}
	
	semantic := InstructionSemantic{
		Operation: opcode,
		Operands:  operandCount,
	}
	
	// Classify by category
	switch {
	case isArithmeticOp(opcode):
		semantic.Category = "ARITHMETIC"
	case isMemoryOp(opcode):
		semantic.Category = "MEMORY"
	case isControlFlowOp(opcode):
		semantic.Category = "CONTROL"
		semantic.IsCondition = isConditionalOp(opcode)
	case isStackOp(opcode):
		semantic.Category = "STACK"
	case isBitwiseOp(opcode):
		semantic.Category = "BITWISE"
	case isFloatingPointOp(opcode):
		semantic.Category = "FLOAT"
	default:
		semantic.Category = "OTHER"
	}
	
	// Check for crypto patterns
	semantic.IsCrypto = sa.cryptoPatterns[opcode] || isCryptoPattern(inst.Operands)
	if semantic.IsCrypto {
		semantic.Category = "CRYPTO"
	}
	
	// Check for API calls
	semantic.IsAPI = isAPICall(opcode, inst.Operands)
	
	// Create normalized representation (architecture-independent)
	semantic.Normalized = fmt.Sprintf("%s:%s:%d", semantic.Category, semantic.Operation, operandCount)
	
	return semantic
}

func (sa *SemanticAnalyzer) computeStructuralHash(cfg *opb.ControlFlowGraph) string {
	// Create structure-based hash (ignoring addresses)
	var elements []string
	
	// Sort blocks by semantic content, not address
	blockHashes := make([]string, 0)
	for _, block := range cfg.BasicBlocks {
		semantic := sa.normalizeBasicBlock(block)
		blockHashes = append(blockHashes, semantic.SemanticHash)
	}
	sort.Strings(blockHashes)
	
	// Add edge patterns
	edgePatterns := make([]string, 0)
	for _, edge := range cfg.Edges {
		pattern := fmt.Sprintf("%s", edge.Type.String())
		edgePatterns = append(edgePatterns, pattern)
	}
	sort.Strings(edgePatterns)
	
	elements = append(elements, strings.Join(blockHashes, "|"))
	elements = append(elements, strings.Join(edgePatterns, "|"))
	
	hashInput := strings.Join(elements, "||")
	hash := sha256.Sum256([]byte(hashInput))
	return fmt.Sprintf("%x", hash)[:32]
}

func (sa *SemanticAnalyzer) countLoops(cfg *opb.ControlFlowGraph) int {
	// Simple loop detection: back edges in CFG
	loops := 0
	
	for _, edge := range cfg.Edges {
		// Check if this is a back edge (destination comes before source)
		if sa.isBackEdge(edge, cfg.BasicBlocks) {
			loops++
		}
	}
	
	return loops
}

func (sa *SemanticAnalyzer) computeBranchingFactor(cfg *opb.ControlFlowGraph) float64 {
	if len(cfg.BasicBlocks) == 0 {
		return 0.0
	}
	
	totalSuccessors := 0
	for _, block := range cfg.BasicBlocks {
		totalSuccessors += len(block.Successors)
	}
	
	return float64(totalSuccessors) / float64(len(cfg.BasicBlocks))
}

func (sa *SemanticAnalyzer) computeCallDepth(cfg *opb.ControlFlowGraph) int {
	maxDepth := 0
	
	for _, function := range cfg.Functions {
		depth := len(function.BasicBlockIds)
		if depth > maxDepth {
			maxDepth = depth
		}
	}
	
	return maxDepth
}

func (sa *SemanticAnalyzer) extractSemanticPatterns(block *opb.BasicBlock) []string {
	patterns := make([]string, 0)
	
	if len(block.Instructions) < 2 {
		return patterns
	}
	
	// Extract instruction sequence patterns (length 2-3)
	for i := 0; i < len(block.Instructions)-1; i++ {
		inst1 := sa.classifyInstruction(block.Instructions[i])
		inst2 := sa.classifyInstruction(block.Instructions[i+1])
		
		pattern := fmt.Sprintf("%s->%s", inst1.Category, inst2.Category)
		patterns = append(patterns, pattern)
		
		// Three-instruction patterns
		if i < len(block.Instructions)-2 {
			inst3 := sa.classifyInstruction(block.Instructions[i+2])
			pattern3 := fmt.Sprintf("%s->%s->%s", inst1.Category, inst2.Category, inst3.Category)
			patterns = append(patterns, pattern3)
		}
	}
	
	return patterns
}

func (sa *SemanticAnalyzer) extractAPICallSequences(block *opb.BasicBlock) []string {
	apiCalls := make([]string, 0)
	
	for _, inst := range block.Instructions {
		if isAPICall(inst.Opcode, inst.Operands) {
			// Extract API name from operands or symbolic info
			apiName := extractAPIName(inst.Operands)
			if apiName != "" {
				apiCalls = append(apiCalls, apiName)
			}
		}
	}
	
	return apiCalls
}

func (sa *SemanticAnalyzer) analyzeDataFlowPatterns(cfg *opb.ControlFlowGraph) []string {
	patterns := make([]string, 0)
	
	// Simple data flow patterns based on instruction sequences
	for _, block := range cfg.BasicBlocks {
		if len(block.Instructions) >= 2 {
			// Look for common data flow patterns like MOV->ARITHMETIC->MOV
			for i := 0; i < len(block.Instructions)-2; i++ {
				inst1 := sa.classifyInstruction(block.Instructions[i])
				inst2 := sa.classifyInstruction(block.Instructions[i+1])
				inst3 := sa.classifyInstruction(block.Instructions[i+2])
				
				if inst1.Category == "MEMORY" && inst2.Category == "ARITHMETIC" && inst3.Category == "MEMORY" {
					patterns = append(patterns, "LOAD_COMPUTE_STORE")
				}
				
				if inst1.Category == "MEMORY" && inst2.Category == "CONTROL" {
					patterns = append(patterns, "LOAD_BRANCH")
				}
			}
		}
	}
	
	return removeDuplicatesAndSort(patterns)
}

func (sa *SemanticAnalyzer) generateCFGEmbedding(semantic *SemanticCFG) []float64 {
	// Create a simple embedding vector for ML comparison
	embedding := make([]float64, 20) // 20-dimensional embedding
	
	// Structural features
	embedding[0] = float64(len(semantic.NormalizedBlocks))
	embedding[1] = float64(semantic.LoopCount)
	embedding[2] = semantic.BranchingFactor
	embedding[3] = float64(semantic.CallDepth)
	
	// Pattern counts
	embedding[4] = float64(len(semantic.SemanticPatterns))
	embedding[5] = float64(len(semantic.APICallSequences))
	embedding[6] = float64(len(semantic.DataFlowPatterns))
	
	// Instruction category distribution
	categories := map[string]int{"ARITHMETIC": 7, "MEMORY": 8, "CONTROL": 9, "STACK": 10, "BITWISE": 11, "FLOAT": 12, "CRYPTO": 13}
	for _, block := range semantic.NormalizedBlocks {
		for _, instType := range block.InstructionTypes {
			if idx, exists := categories[instType]; exists && idx < len(embedding) {
				embedding[idx]++
			}
		}
	}
	
	// Normalize instruction counts
	total := float64(0)
	for i := 7; i < 14; i++ {
		total += embedding[i]
	}
	if total > 0 {
		for i := 7; i < 14; i++ {
			embedding[i] /= total
		}
	}
	
	// Control flow diversity
	embedding[14] = sa.computeControlFlowDiversity(semantic)
	
	// Remaining dimensions for future use
	for i := 15; i < len(embedding); i++ {
		embedding[i] = 0.0
	}
	
	return embedding
}

func (sa *SemanticAnalyzer) CompareCFGs(cfg1, cfg2 *SemanticCFG) *CFGSimilarityResult {
	result := &CFGSimilarityResult{}
	
	// Structural similarity
	result.StructuralSimilarity = computeStructuralSimilarity(cfg1, cfg2)
	
	// Semantic pattern similarity
	result.PatternSimilarity = computeSetSimilarity(cfg1.SemanticPatterns, cfg2.SemanticPatterns)
	
	// API call similarity
	result.APISimilarity = computeSetSimilarity(cfg1.APICallSequences, cfg2.APICallSequences)
	
	// Data flow similarity
	result.DataFlowSimilarity = computeSetSimilarity(cfg1.DataFlowPatterns, cfg2.DataFlowPatterns)
	
	// Embedding similarity (cosine similarity)
	result.EmbeddingSimilarity = computeCosineSimilarity(cfg1.CFGEmbedding, cfg2.CFGEmbedding)
	
	// Overall similarity (weighted average)
	result.OverallSimilarity = (result.StructuralSimilarity*0.3 + 
								result.PatternSimilarity*0.25 + 
								result.APISimilarity*0.15 + 
								result.DataFlowSimilarity*0.1 + 
								result.EmbeddingSimilarity*0.2)
	
	return result
}

type CFGSimilarityResult struct {
	StructuralSimilarity  float64
	PatternSimilarity     float64
	APISimilarity         float64
	DataFlowSimilarity    float64
	EmbeddingSimilarity   float64
	OverallSimilarity     float64
}

// Helper functions
func initCryptoPatterns() map[string]bool {
	return map[string]bool{
		"AES": true, "XOR": true, "ROL": true, "ROR": true,
		"PXOR": true, "AESENC": true, "AESDEC": true,
		"SHA1": true, "SHA256": true, "MD5": true,
	}
}

func initAPIPatterns() map[string]bool {
	return map[string]bool{
		"CALL": true, "SYSCALL": true, "INT": true,
	}
}

func isArithmeticOp(op string) bool {
	return contains([]string{"ADD", "SUB", "MUL", "DIV", "IMUL", "IDIV", "INC", "DEC", "NEG"}, op)
}

func isMemoryOp(op string) bool {
	return contains([]string{"MOV", "LEA", "LDS", "LES", "LFS", "LGS", "LSS", "MOVS", "LODS", "STOS"}, op)
}

func isControlFlowOp(op string) bool {
	return contains([]string{"JMP", "JA", "JAE", "JB", "JBE", "JE", "JG", "JGE", "JL", "JLE", "JNE", "CALL", "RET"}, op)
}

func isConditionalOp(op string) bool {
	return contains([]string{"JA", "JAE", "JB", "JBE", "JE", "JG", "JGE", "JL", "JLE", "JNE", "JO", "JP", "JS"}, op)
}

func isStackOp(op string) bool {
	return contains([]string{"PUSH", "POP", "PUSHF", "POPF", "PUSHA", "POPA"}, op)
}

func isBitwiseOp(op string) bool {
	return contains([]string{"AND", "OR", "XOR", "NOT", "SHL", "SHR", "SAL", "SAR", "ROL", "ROR"}, op)
}

func isFloatingPointOp(op string) bool {
	return contains([]string{"FADD", "FSUB", "FMUL", "FDIV", "FLD", "FST", "FCOS", "FSIN", "FSQRT"}, op)
}

func isCryptoPattern(operands string) bool {
	crypto_keywords := []string{"aes", "sha", "md5", "rsa", "des", "crypto", "hash", "cipher"}
	operands_lower := strings.ToLower(operands)
	for _, keyword := range crypto_keywords {
		if strings.Contains(operands_lower, keyword) {
			return true
		}
	}
	return false
}

func isAPICall(opcode, operands string) bool {
	return strings.Contains(strings.ToUpper(opcode), "CALL") && strings.Contains(operands, "@")
}

func extractAPIName(operands string) string {
	if strings.Contains(operands, "@") {
		parts := strings.SplitN(operands, "@", 2) // Split only at first @
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func (sa *SemanticAnalyzer) getControlFlowType(inst *opb.Instruction) string {
	opcode := strings.ToUpper(inst.Opcode)
	switch {
	case contains([]string{"RET"}, opcode):
		return "RETURN"
	case contains([]string{"CALL"}, opcode):
		return "CALL"
	case contains([]string{"JMP"}, opcode):
		return "UNCONDITIONAL_JUMP"
	case isConditionalOp(opcode):
		return "CONDITIONAL_JUMP"
	default:
		return "FALL_THROUGH"
	}
}

func (sa *SemanticAnalyzer) isBackEdge(edge *opb.ControlFlowEdge, blocks []*opb.BasicBlock) bool {
	// Simple heuristic: if edge goes to a block with smaller index, it might be a back edge
	fromIdx, toIdx := -1, -1
	for i, block := range blocks {
		if block.Id == edge.From {
			fromIdx = i
		}
		if block.Id == edge.To {
			toIdx = i
		}
	}
	return fromIdx > toIdx && toIdx >= 0
}

func (sa *SemanticAnalyzer) computeControlFlowDiversity(semantic *SemanticCFG) float64 {
	controlTypes := make(map[string]int)
	for _, block := range semantic.NormalizedBlocks {
		controlTypes[block.ControlFlowType]++
	}
	
	// Shannon entropy of control flow types
	total := float64(len(semantic.NormalizedBlocks))
	entropy := 0.0
	for _, count := range controlTypes {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * (float64(count) / total)
		}
	}
	return entropy
}

func computeStructuralSimilarity(cfg1, cfg2 *SemanticCFG) float64 {
	if cfg1.StructuralHash == cfg2.StructuralHash {
		return 1.0
	}
	
	// Compare structural metrics
	similarities := []float64{
		1.0 - abs(float64(cfg1.LoopCount-cfg2.LoopCount))/max(float64(cfg1.LoopCount), float64(cfg2.LoopCount), 1.0),
		1.0 - abs(cfg1.BranchingFactor-cfg2.BranchingFactor)/max(cfg1.BranchingFactor, cfg2.BranchingFactor, 1.0),
		1.0 - abs(float64(cfg1.CallDepth-cfg2.CallDepth))/max(float64(cfg1.CallDepth), float64(cfg2.CallDepth), 1.0),
	}
	
	sum := 0.0
	for _, sim := range similarities {
		sum += sim
	}
	
	return sum / float64(len(similarities))
}

func computeSetSimilarity(set1, set2 []string) float64 {
	if len(set1) == 0 && len(set2) == 0 {
		return 1.0
	}
	
	if len(set1) == 0 || len(set2) == 0 {
		return 0.0
	}
	
	map1 := make(map[string]bool)
	for _, item := range set1 {
		map1[item] = true
	}
	
	intersection := 0
	for _, item := range set2 {
		if map1[item] {
			intersection++
		}
	}
	
	union := len(set1) + len(set2) - intersection
	return float64(intersection) / float64(union) // Jaccard similarity
}

func computeCosineSimilarity(vec1, vec2 []float64) float64 {
	if len(vec1) != len(vec2) || len(vec1) == 0 {
		return 0.0
	}
	
	dotProduct := 0.0
	norm1 := 0.0
	norm2 := 0.0
	
	for i := 0; i < len(vec1); i++ {
		dotProduct += vec1[i] * vec2[i]
		norm1 += vec1[i] * vec1[i]
		norm2 += vec2[i] * vec2[i]
	}
	
	if norm1 == 0.0 || norm2 == 0.0 {
		return 0.0
	}
	
	return dotProduct / (norm1 * norm2)
}

func removeDuplicatesAndSort(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	sort.Strings(result)
	return result
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func max(values ...float64) float64 {
	if len(values) == 0 {
		return 0
	}
	maxVal := values[0]
	for _, v := range values[1:] {
		if v > maxVal {
			maxVal = v
		}
	}
	return maxVal
}

