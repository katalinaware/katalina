package main

import (
	"bufio"
	"io"
	"math"

	opb "github.com/appsworld/katalinaware/protos"
)

type DistFeat struct {
	BitDist [][]uint
}

// makeIntZeros returns a Matrix2D with x rows and y columns, initialized with zeros.
func makeIntZeros(x, y uint) *opb.Matrix2D {
	var matrix2D opb.Matrix2D
	for i := uint(0); i < x; i++ {
		var row opb.Row
		for j := uint(0); j < y; j++ {
			row.Values = append(row.Values, 0)
		}
		matrix2D.Rows = append(matrix2D.Rows, &row)
	}
	return &matrix2D
}

// rShiftA returns a new slice with each element in arr right-shifted by sBy bits.
func rShiftA(arr []int32, sBy int32) []int32 {
	res := make([]int32, len(arr))
	for idx, i := range arr {
		res[idx] = i >> sBy
	}
	return res
}

// Use unsigned integer for minLen so we don't have integer underflow.
func binCount(arr []int32, minLen int32) []int32 {
	var res []int32
	// Use a slice of fixed size instead of a map to count the occurrences of each value
	var valCount = make([]int32, 256)
	var max int32
	for _, val := range arr {
		valCount[val]++
		if val > max {
			max = val
		}
	}
	for i := int32(0); i <= max; i++ {
		res = append(res, valCount[i])
	}
	sizeRes := int32(len(res))
	if sizeRes < minLen {
		dVal := minLen - sizeRes
		for i := int32(0); i < dVal; i++ {
			res = append(res, 0)
		}
	}
	return res
}

/*
*

		perBinEntropy calculates the per-bin entropy of a given block of data.
	 	The per-bin entropy is a measure of the amount of randomness or unpredictability in the block.
		It is calculated by dividing the block into bins, counting the number of occurrences of each value in each bin,
		and then using the bin count to calculate the entropy of the block. The block is first right-shifted by 4 bits,
		which reduces the number of bins from 256 to 16. Then, the bin count of each value in the block is calculated
		using the binCount function. The entropy of each bin is calculated using the formula: ent = -p * log2(p), where p is the
		probability of a value occurring in the bin. The total entropy of the block is the sum of the entropies of all the bins,
		multiplied by 2. If the total entropy is equal to 16, it is set to 15 to avoid overflow.

*
*/
func perBinEntropy(block []int32) ([]int32, int) {
	window := uint(2048)
	var totEnt float64
	cBlock := rShiftA(block, 4)

	cBlock = binCount(cBlock, 16)
	for _, b := range cBlock {
		divR := float64(b) / float64(window)

		// Avoid adding 0 elements to prevent division by 0 in the future.
		if b > 0 {
			// Account for reducing 256 bins to 16 bins.
			logSize := math.Log2(divR)
			ent := -divR * logSize
			totEnt += ent
		}
	}
	totEnt *= 2
	histBin := int((totEnt * 2))
	if histBin == 16 {
		histBin = 15
	}
	return cBlock, histBin
}

func selectNStrides(arr []int32, width int32, shape int32, step int) [][]int32 {
	values := make([][]int32, 0, int(shape)/step+1)
	if step == 0 {
		values = append(values, arr[:step])
		return values
	}
	for i := 0; i < len(arr)-int(width)+1; i++ {
		resRow := arr[i : i+int(width)]
		if i%step == 0 {
			values = append(values, resRow)
		}
		if int32(len(values)) >= shape {
			break
		}
	}
	return values
}

// byteDistribution returns the byte distribution of a given Mach-O file.
func byteDistribution(bts *MachoReader) *opb.Matrix2D {
	bFeat := makeIntZeros(16, 16)
	emptyMatrix := &opb.Matrix2D{Rows: []*opb.Row{
		{Values: []int32{}},
	}}

	stat, err := bts.File.Stat()
	if err != nil {
		return emptyMatrix
	}

	_, err = bts.File.Seek(0, io.SeekStart)
	if err != nil {
		ErrorLogger.Printf("error seeking to the beginning of the file: %v", err)
		return emptyMatrix
	}

	iObj := make([]int32, stat.Size())
	reader := bufio.NewReader(bts.File)
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
		}
		iObj = append(iObj, int32(b))
	}

	step := 1024
	window := 2048
	totSize := len(iObj)
	if totSize < window {
		binBlock, histBin := perBinEntropy(iObj)
		bFeat.Rows[histBin].Values = binBlock
	} else {
		blocks := selectNStrides(iObj, int32(window), int32(totSize), step)
		for _, block := range blocks {
			binBlock, histBin := perBinEntropy(block)
			copy(bFeat.Rows[histBin].Values, binBlock)
		}
	}
	return bFeat
}
