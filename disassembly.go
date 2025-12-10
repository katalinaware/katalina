package main

import (
	"fmt"

	opb "github.com/appsworld/katalinaware/protos"
	"golang.org/x/arch/x86/x86asm"
)

type Instruction struct {
	Op      string
	Address string
	Decode  string
}

func disassembly(f *MachoReader) ([]*Instruction, error) {
	instructions := []*Instruction{}
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

		for len(code) > 0 && startAddr < endAddr {
			inst, err := x86asm.Decode(code, 64)
			if err != nil {
				break
			}

			if inst.Len > 0 {
				instructions = append(instructions, &Instruction{
					Op:      inst.Op.String(),
					Address: fmt.Sprintf("%#x", startAddr),
					Decode:  inst.String(),
				})

				startAddr += uint64(inst.Len)
				code = code[inst.Len:]
			} else {
				code = code[1:]
			}
		}
	}

	return instructions, nil
}

/*
considering pairs of opcodes that are adjacent in the list. This means that the co-occurrence frequencies will only be calculated for pairs of opcodes
that appear immediately after each other in the list, and will not include opcodes that are separated by other opcodes or values.
*/
func OpcodeOccurrence(opcodes []*Instruction) map[string]map[string]float64 {
	opcodeCooccurrence := make(map[string]map[string]float64)
	for i, opcode1 := range opcodes {
		if _, ok := opcodeCooccurrence[opcode1.Op]; !ok {
			opcodeCooccurrence[opcode1.Op] = make(map[string]float64)
		}
		for _, opcode2 := range opcodes[i+1:] {
			opcodeCooccurrence[opcode1.Op][opcode2.Op]++
		}
	}

	// Calculate the co-occurrence frequencies by dividing the co-occurrence count for each pair by the total number of opcodes
	for opcode1, cooccurrence := range opcodeCooccurrence {
		for opcode2, count := range cooccurrence {
			opcodeCooccurrence[opcode1][opcode2] = count / float64(len(opcodes))
		}
	}

	return opcodeCooccurrence
}

func OpcodeFrequency(opcodes []*Instruction) map[string]float64 {
	opcodeFrequency := make(map[string]float64)

	for _, opcode := range opcodes {
		opcodeFrequency[opcode.Op]++
	}

	for opcode, count := range opcodeFrequency {
		opcodeFrequency[opcode] = handleNanFloat(count / float64(len(opcodes)))
	}
	return opcodeFrequency
}

// DisasFeats finds features that pertain to just the opcodes.
// It finds pure opcode frequency as well as their occurrence with each other.
func DisasFeats(f *MachoReader) *opb.DisasFeatures {
	disas, err := disassembly(f)
	if err != nil {
		ErrorLogger.Printf("could not get disassembly : %v", err)
	}
	disFeat := &opb.DisasFeatures{
		OpCodeFrequency:  map[string]float64{},
		ControlFlowGraph: &opb.ControlFlowGraph{},
	}
	disFeat.OpCodeFrequency = OpcodeFrequency(disas)
	
	// Only generate CFG if explicitly requested (expensive operation)
	if generateCFG {
		cfg := NewCFGBuilder()
		controlFlowGraph, err := cfg.GenerateCFG(f)
		if err != nil {
			WarningLogger.Printf("could not generate control flow graph: %v", err)
			disFeat.ControlFlowGraph = &opb.ControlFlowGraph{}
		} else {
			disFeat.ControlFlowGraph = controlFlowGraph
			InfoLogger.Printf("Generated CFG with %d basic blocks, %d functions, %d edges", 
				len(controlFlowGraph.BasicBlocks), len(controlFlowGraph.Functions), len(controlFlowGraph.Edges))
			
			// Add semantic analysis
			semanticAnalyzer := NewSemanticAnalyzer()
			semanticCFG := semanticAnalyzer.AnalyzeCFGSemantics(controlFlowGraph)
			InfoLogger.Printf("Semantic analysis: hash=%s, loops=%d, branching=%.2f, patterns=%d", 
				semanticCFG.StructuralHash[:8], semanticCFG.LoopCount, semanticCFG.BranchingFactor, len(semanticCFG.SemanticPatterns))
		}
	} else {
		// Skip CFG generation for performance - provide empty CFG
		disFeat.ControlFlowGraph = &opb.ControlFlowGraph{}
		InfoLogger.Printf("CFG generation skipped (use --generate_cfg to enable)")
	}
	
	return disFeat
}
