package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	opb "github.com/appsworld/katalinaware/protos"
	"github.com/pkg/errors"
)

var (
	emptyHashes = &opb.Hash{
		Md5:    "",
		Sha1:   "",
		Sha256: "",
	}

	emptyMachoHeader = &opb.MachoHeader{
		Magic:          "",
		CpuType:        "",
		CpuSubType:     "",
		HeaderFileType: "",
		NumCmds:        0,
		CmdSize:        0,
		Flags:          []string{},
		NumFlags:       0,
	}

	emptySpecialSlot = &opb.SpecialSlot{
		PsListHash:       "",
		RequirementsHash: "",
		EntitlementHash:  "",
		CodeResourceHash: "",
	}

	emptyCodeDir = &opb.CodeDirectory{
		Id:                       "",
		TeamId:                   "",
		SpecialSlots:             emptySpecialSlot,
		HashType:                 0,
		ExtractedCdhash:          "",
		ExtractedCdhashFull:      "",
		ComputedSha1Cdhash:       "",
		ComputedSha1CdhashFull:   "",
		ComputedSha256Cdhash:     "",
		ComputedSha256CdhashFull: "",
		Notarization: &opb.NotarizationInfo{
			IsNotarized:  false,
			Timestamp:    0,
			TimestampUtc: "",
			Error:        "",
			RecordName:   "",
			SignedTicket: "",
			Deleted:      false,
		},
	}

	emptyEntitlements = &opb.Entitlements{
		Entitlements:        []string{},
		EntHash:             "",
		PlistHash:           "",
		HasTaskAllow:        false,
		HasAllowUnsignedMem: false,
		HasJitAllow:         false,
	}

	emptyObjcFeatures = &opb.ObjCFeatures{
		MethodNames: []string{},
		MethodHash:  "",
		ClassNames:  []string{},
		ClassHash:   "",
	}

	emptySwiftFeatures = &opb.SwiftFeatures{
		TypeNames: []string{},
		TypeHash:  "",
	}

	emptySymbol = &opb.Symbol{
		ExtSyms:    []string{},
		ExtSymHash: "",
		AllSyms:    []string{},
		AllSymHash: "",
	}

	emptyDylib = &opb.Dylib{
		Name:              "",
		CurrentVersion:    "",
		CompatibleVersion: "",
		Time:              0,
	}

	emptyDylibFeatures = &opb.DylibFeatures{
		Dylibs:            []*opb.Dylib{emptyDylib},
		NumDylibs:         0,
		HasAudiovisualCap: false,
		HasSecurityCap:    false,
		HasLocationCap:    false,
		HasPersonalDat:    false,
		HasDiskCap:        false,
	}

	emptySection = &opb.Section{
		NumSections:          0,
		NumSecFlags:          0,
		UniqueNumSecFlags:    0,
		NumSecZeroSize:       0,
		NumSecNonZeroSize:    0,
		NumTextSec:           0,
		NumDataSections:      0,
		NumAttributes:        0,
		NumOfReloc:           0,
		UniqueNumRelocTypes:  0,
		SumSecSize:           0,
		HasDebugAttribute:    false,
		HasSelfModifyingCode: false,
		HasCStringLiterals:   false,
		HasStripSymbols:      false,
		MeanTextSecEntropy:   0.0,
		MeanSecNameEntropy:   0.0,
		ModeSecNameEntropy:   0.0,
		MomentSecNameEntropy: 0.0,
		SectionEntropies:     make(map[string]float64),
	}

	emptySegment = &opb.Segment{
		NumSegments: 0,
		// A default HasEmptyPageZeroSeg of false is not what we need as that indicates
		// a potentially malicious binary.
		HasEmptyPageZeroSeg: true,
		SumSegMemSize:       0,
		SumSegFileSize:      0,
		TxtSegVmProt:        "",
		DataSegVmProt:       "",
		LnkEditSegVmProt:    "",
		UniqueSegFlags:      []string{},
	}

	emptyDySymTabFeatures = &opb.DySymTabFeatures{
		NumExternalDefines:   0,
		NumExternalReference: 0,
		NumExternalReloc:     0,
	}

	emptyDyldInfo = &opb.DyldInfo{
		RebaseSize:   0,
		BindSize:     0,
		LazyBindSize: 0,
		ExportSize:   0,
	}

	emptyCeryFeaturesML = &opb.CertFeaturesML{
		IsSigned:             false,
		IsSelfSigned:         false,
		IsSignedByCa:         false,
		IsCertificateRevoked: false,
		IsAdHoc:              false,
	}

	emptyDisasFeatures = &opb.DisasFeatures{
		OpCodeFrequency:  map[string]float64{},
		ControlFlowGraph: &opb.ControlFlowGraph{},
	}

	// Deprecated: Use newEmptyRawStringFeatures() for thread safety
	emptyRawStringFeatures = &opb.RawStringFeat{
		AllStrings:              "",
		PathsBestEffort:         []string{},
		UniquePlistPaths:        []string{},
		PathsWithFString:        []string{},
		UrlWithFString:          []string{},
		UniqueDomains:           []string{},
		UrlBestEffort:           []string{},
		UniqueShells:            []string{},
		UniqueIoDeviceListeners: []string{},
		UniquePotentialHwRecon:  []string{},
		UniqueSymbolsWithAt:     []string{},
		// Information Stealer Detection - Matched Strings
		MatchedKeychainAccess:  []string{},
		MatchedDiscordWebhooks: []string{},
		// macOS Security Bypass Detection - Matched Strings
		MatchedGatekeeperBypass:  []string{},
		MatchedQuarantineRemoval: []string{},
	}

	emptyModelStrings = &opb.StringModel{
		NumStrings:       0,
		MaxLength:        0,
		NumLongerThanAvg: 0,
		AvgLength:        0.0,
		EntStats: &opb.EntStat{
			MaxEntropy:  0.0,
			ModeEntropy: 0.0,
			MeanEntropy: 0.0,
		},
		NumPaths:            0,
		NumUniquePlistPaths: 0,
		NumUrl:              0,
		NumUrlWithFString:   0,
		NumPathWithFString:  0,
		NumUniqueDomains:    0,
		Persistence: &opb.Persistence{
			NumLaunchAgentPath:   0,
			NumLaunchDaemonPath:  0,
			NumStartupItems:      0,
			NumScriptingAddition: 0,
			NumLoginWindow:       0,
			NumLoginItems:        0,
			NumShellStartupFiles: 0,
			NumCrontab:           0,
		},
		PrivEsc: &opb.PrivEsc{
			NumSqlLite: 0,
			NumTcc:     0,
		},
		Encodings: &opb.Encodings{
			NumBase64: 0,
			NumCerts:  0,
		},
		NumUniqueShells:      0,
		NumIoDeviceListeners: 0,
		NumPotentialHwRecon:  0,
		// Information Stealer Detection Metrics
		NumBrowserPaths:    0,
		NumKeychainAccess:  0,
		NumTelegramApi:     0,
		NumFakeAuthPrompts: 0,
		NumDiscordWebhooks: 0,
		// macOS Security Bypass Detection Metrics
		NumGatekeeperBypass:  0,
		NumQuarantineRemoval: 0,
	}

	emptyCertificate = &opb.Certificate{
		Sans:         []string{},
		Emails:       []string{},
		IpAddresses:  []string{},
		SerialNumber: "",
		Issuer: &opb.CertIssuerSubj{
			IssuerName:     "",
			IssuerCountry:  "",
			IssuerOrg:      "",
			SubjectName:    "",
			SubjectOrg:     "",
			SubjectOrgUnit: "",
		},
		ValidFrom: "",
		ValidTo:   "",
	}

	emptyNonModelFeat = &opb.NonModelFeat{
		Certificates:  []*opb.Certificate{emptyCertificate},
		Uuid:          "",
		RawStringFeat: emptyRawStringFeatures,
		SymbolInfo:    emptySymbol,
	}

	emptyModelFeat = &opb.ModelFeat{
		CodeDirectory:      emptyCodeDir,
		ObjectiveCFeatures: emptyObjcFeatures,
		SwiftFeatures:      emptySwiftFeatures,
		SegmentFeatures:    emptySegment,
		SectionFeatures:    emptySection,
		DylibFeatures:      emptyDylibFeatures,
		DySymTabFeatures:   emptyDySymTabFeatures,
		DyldInfo:           emptyDyldInfo,
		Entitlements:       emptyEntitlements,
		CertFeatures:       emptyCeryFeaturesML,
		ByteEntropyDist: &opb.Matrix2D{
			Rows: []*opb.Row{
				{Values: []int32{}},
			},
		},
		Strings:          emptyModelStrings,
		AssemblyFeatures: emptyDisasFeatures,
	}
)

const (
	// minPrintableLength is the minimum length of a printable string.
	minPrintableLength = 4
)

func emptyAnalysisOutput() *opb.AnalysisOutput {
	return &opb.AnalysisOutput{
		FilePath: "",
		ProcessedFileHashes: &opb.Hash{
			Md5:    "",
			Sha1:   "",
			Sha256: "",
		},
		FileLineage: []*opb.FileLineageStep{},
		MachoHeader: &opb.MachoHeader{
			Magic:          "",
			CpuType:        "",
			CpuSubType:     "",
			HeaderFileType: "",
			NumCmds:        0,
			CmdSize:        0,
			Flags:          []string{},
			NumFlags:       0,
		},
		IsFat:           false,
		SelectedFatArch: "",
		NonModelFeat: &opb.NonModelFeat{
			Certificates:  []*opb.Certificate{},
			Uuid:          "",
			RawStringFeat: &opb.RawStringFeat{},
			SymbolInfo:    &opb.Symbol{},
		},
		ModelFeat: &opb.ModelFeat{
			CodeDirectory: &opb.CodeDirectory{},
			ObjectiveCFeatures: &opb.ObjCFeatures{
				MethodNames: []string{},
				MethodHash:  "",
				ClassNames:  []string{},
				ClassHash:   "",
			},
			SwiftFeatures: &opb.SwiftFeatures{
				TypeNames: []string{},
				TypeHash:  "",
			},
			SegmentFeatures:  &opb.Segment{},
			SectionFeatures:  &opb.Section{},
			DylibFeatures:    &opb.DylibFeatures{},
			DySymTabFeatures: &opb.DySymTabFeatures{},
			DyldInfo:         &opb.DyldInfo{},
			Entitlements:     &opb.Entitlements{},
			CertFeatures:     &opb.CertFeaturesML{},
			ByteEntropyDist:  &opb.Matrix2D{},
			Strings:          &opb.StringModel{},
			AssemblyFeatures: &opb.DisasFeatures{},
		},
	}
}

// createFileLineage creates a lineage chain from original file to processed binary
func createFileLineage(originalPath string, originalHashes *opb.Hash, r *MachoReader) []*opb.FileLineageStep {
	var lineage []*opb.FileLineageStep

	// Step 0: Original file
	step0 := &opb.FileLineageStep{
		Step:        0,
		Description: getOriginalFileDescription(originalPath),
		FilePath:    originalPath,
		Hashes:      originalHashes,
	}
	lineage = append(lineage, step0)

	// Handle archive extraction step
	if r.ExtractedFileHashes != nil && r.ExtractedFileHashes.Sha256 != "" && r.ExtractedFileHashes != emptyHashes {
		step1 := &opb.FileLineageStep{
			Step:        1,
			Description: "Extracted from archive",
			FilePath:    r.filePath,
			Hashes:      r.ExtractedFileHashes,
		}
		lineage = append(lineage, step1)
	}

	// Handle FAT binary architecture extraction step
	if r.IsFat && r.MachoReader != nil && r.MachoReader.CPU != 0 {
		stepNum := len(lineage)
		var archHashes *opb.Hash

		if r.ArchitectureHashes != nil && r.ArchitectureHashes.Sha256 != "" && r.ArchitectureHashes != emptyHashes {
			archHashes = r.ArchitectureHashes
		} else {
			archHashes = nil // Will be set by caller with actual processed binary hashes
		}

		archStep := &opb.FileLineageStep{
			Step:        int32(stepNum),
			Description: fmt.Sprintf("%s architecture from universal binary", r.MachoReader.CPU.String()),
			FilePath:    r.filePath,
			Hashes:      archHashes,
		}
		lineage = append(lineage, archStep)
	}

	return lineage
}

// getOriginalFileDescription returns a description for the original file based on its extension
func getOriginalFileDescription(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".dmg":
		return "Original DMG file"
	case ".pkg":
		return "Original PKG file"
	case ".app":
		return "Original app bundle"
	case ".zip":
		return "Original ZIP archive"
	default:
		if strings.Contains(filePath, ".app/") {
			return "Binary from app bundle"
		}
		return "Original binary file"
	}
}

// getProcessedFileHashes determines what the actual processed file hashes should be
func getProcessedFileHashes(r *MachoReader, originalHashes *opb.Hash) *opb.Hash {
	// For FAT binaries, use the architecture-specific hashes
	if r.IsFat && r.ArchitectureHashes != nil && r.ArchitectureHashes.Sha256 != "" && r.ArchitectureHashes != emptyHashes {
		return r.ArchitectureHashes
	}
	// If we have extracted file hashes from archive, use those
	if r.ExtractedFileHashes != nil && r.ExtractedFileHashes.Sha256 != "" && r.ExtractedFileHashes != emptyHashes {
		return r.ExtractedFileHashes
	}
	// Otherwise, we processed the original file
	return originalHashes
}

// StringSet implements a string set for storaing a unique number of strings.
type StringSet struct {
	set map[string]bool
}

func (s *StringSet) NewStringSet() {
	s.set = make(map[string]bool)
}

// Contains checks if the string set contains a given input string.
func (s *StringSet) Contains(input string) bool {
	_, ok := s.set[input]
	return ok
}

// Add adds the input string to the string set.
func (s *StringSet) Add(input ...string) {
	for _, val := range input {
		if val != "" {
			s.set[val] = true
		}
	}
}

// Remove removes the given input string from the stringset
func (s *StringSet) Remove(input string) {
	delete(s.set, input)
}

// Strings returns the string set in sorted ascending order.
func (s *StringSet) Strings() []string {
	keys := []string{}
	for k := range s.set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Len returns the len of the string set.
func (s *StringSet) Len() int {
	return len(s.set)
}

type Ents struct {
	XMLName xml.Name `xml:"plist"`
	Dict    XMLDict  `xml:"dict"`
}

type XMLDict struct {
	Key    []string `xml:"key"`
	String []string `xml:"string"`
}

func ParsePSList(path string) ([]string, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("error: file length is 0")
	}
	fileContents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error: getting file contents %v", err)
	}
	return getPsLists(fileContents)
}

// getPsLists returns a list of all the pslist entitlements in the file.
func getPsLists(entval []byte) ([]string, error) {
	if len(entval) == 0 {
		return nil, fmt.Errorf("error: entitlements of size 0 bytes")
	}
	ents := &Ents{}
	// So we don't have to deal with the different types
	// We coerce everything into a string: value.
	// Apple Entitlement PSList DTD : https://www.apple.com/DTDs/PropertyList-1.0.dtd
	if err := xml.Unmarshal(entval, ents); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal data")
	}

	return ents.Dict.Key, nil
}

func domainsFromUrls(urls StringSet) StringSet {
	var domains StringSet
	domains.NewStringSet()

	urlStrings := urls.Strings()
	maxUrls := 1000 // Limit processing to first 1000 URLs to prevent performance issues
	if len(urlStrings) > maxUrls {
		InfoLogger.Printf("Limiting URL processing from %d to %d URLs for performance", len(urlStrings), maxUrls)
		urlStrings = urlStrings[:maxUrls]
	}

	for _, val := range urlStrings {
		if val == "" {
			continue
		}

		// Skip obviously malformed URLs that would cause parsing issues
		if len(val) > 2000 { // Skip extremely long URLs
			continue
		}

		if m := reDomain.FindStringSubmatch(val); len(m) > 1 {
			ur, err := url.Parse(m[1])
			if err != nil {
				// Don't log every malformed URL to reduce log spam
				continue
			}
			domains.Add(strings.TrimPrefix(ur.Hostname(), "www."))
		}
	}
	return domains
}

// StringEntropy computes the entropy given a string.
// Implements the naive shannon entropy which handles overlaps.
// For non English language characters we would be off by about +-0.5
func StringEntropy(s string) (e float64) {
	m := make(map[rune]bool)
	for _, r := range s {
		if m[r] {
			continue
		}
		m[r] = true
		n := strings.Count(s, string(r))
		p := float64(n) / float64(len(s))
		e += p * math.Log(p) / math.Log(2)
	}
	return math.Abs(e)
}

func BArrUArry(brr []byte) []uint {
	arr := make([]uint, len(brr))
	for _, b := range brr {
		arr = append(arr, uint(b))
	}
	return arr
}

func isASCII(s []byte) bool {
	isNonASCIIChar := true
	for _, r := range s {
		if r > 127 {
			isNonASCIIChar = false
		}
	}
	return isNonASCIIChar
}

// allStrings returns all printable strings in all available sections in the
// binary that falls between 0x20 and 0x7f and are longer than 5 or more bytes.
func allStrings(r *MachoReader) StringSet {
	var out StringSet
	out.NewStringSet()

	strs, err := stringFromFile(r.File)
	if err != nil {
		ErrorLogger.Println("error retrieving strings from file:", err)
		return out
	}
	out.Add(strs...)

	return out
}

func stringFromFile(file *os.File) ([]string, error) {
	var (
		out          []string
		printableRun []rune
	)

	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("error seeking to the beginning of the file: %v", err)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanRunes)

	for scanner.Scan() {
		r := []rune(scanner.Text())[0]
		if unicode.IsPrint(r) || r == '\t' {
			printableRun = append(printableRun, r)
		} else {
			if len(printableRun) >= minPrintableLength {
				out = append(out, string(printableRun))
			}
			printableRun = []rune{}
		}
	}

	if len(printableRun) >= minPrintableLength {
		out = append(out, string(printableRun))
	}

	return out, nil
}

// getHashes returns a standard set of hashes for a given byte stream.
func getHashes(data []byte) (*opb.Hash, error) {
	hashes := &opb.Hash{}
	var err error
	hashes.Sha256, err = hashObject(data, "sha256")
	if err != nil {
		return hashes, err
	}
	hashes.Sha1, err = hashObject(data, "sha1")
	if err != nil {
		return hashes, err
	}
	hashes.Md5, err = hashObject(data, "md5")
	if err != nil {
		return hashes, err
	}
	return hashes, err
}

// byteEntropy calculates the entropy of an slice of bytes
func byteEntropy(bytes []byte) float64 {
	freq := make(map[byte]int)

	for _, b := range bytes {
		freq[b]++
	}

	var entropy float64
	for _, f := range freq {
		p := float64(f) / float64(len(bytes))
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// handleNanFloat replaces Nan floats or ints with its zero value.
func handleNanFloat(val float64) float64 {
	if math.IsNaN(val) || math.IsInf(val, 0) {
		return 0.0
	}
	return val
}

// saveCertsAsPEM saves the certificates in PEM format
func saveCertsAsPEM(certs []*x509.Certificate) error {
	for i, cert := range certs {
		filename := fmt.Sprintf("cert%d.pem", i)
		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			return err
		}
		fmt.Printf("Saved: %s\n", filename)
	}
	return nil
}
