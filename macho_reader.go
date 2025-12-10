package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	opb "github.com/appsworld/katalinaware/protos"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

const (
	invalidMagic = "invalid magic number"
	// MaxFileSize maximum file size processed by parser.
	MaxFileSize = 1024 * 1024 * 1024
)

// MachoReader contains instance for reading the binary.
// For FAT/universal binaries, each architecture gets its own MachoReader with
// File pointing to a temporary file containing only that architecture's binary data.
type MachoReader struct {
	MachoReader         *macho.File
	File                *os.File // File handle for reading strings (architecture-specific for FAT binaries)
	filePath            string   // Path to the file (temp file path for extracted architectures)
	ByteStream          []uint
	IsFat               bool
	SelectedFatArch     string
	ExtractedFileHashes *opb.Hash // Hash of file extracted from archive (e.g., DMG, ZIP)
	ArchitectureHashes  *opb.Hash // Hash of specific architecture extracted from FAT binary
	isTempFile          bool      // True if filePath points to a temporary file that should be cleaned up
}

var (
	errEmptyFilePath    = errors.New("file path has length 0")
	errNoFATFile        = errors.New("input fat file is empty or contains unrecognized arch")
	errNoMachoCandidate = errors.New("did not find a valid macho candidate from unextracted archive")

	errOpenFileFailed          = "failed to get the file statistics: %v"
	errGetFileStatsFailed      = "failed to open the file: %v"
	errFileGreaterThan2Gig     = "file is greater than 2 Gigabytes: %v"
	errParseMachOFailed        = "could not parse the binary with path : %s"
	errFileNeitherMachoPackage = "file %s, is neither macho or package archive"
	errCleaningTempDir         = "could not clean up temp directory: %v"
	errNoInfoPlist             = "file %v is an archive but does not have an Info.plist"
	errNoContentPaths          = "file %v does not have content paths"
	errExtractArchiveFailed    = "could not extract archive %s : %v"
	errParsePlistFailed        = "error from parsing plist: %v"
	errFailedToParseMacho      = "failed to parse the Mach-O file : %s\n"

	infoFileOpened       = "file successfully opened as a FAT binary"
	infoMachoBeginOpen   = "attempting to open the file as a FAT file"
	infoArchiveBeginOpen = "attempting to open the file as a potential archive"
)

// MachFile will open the file and return MachoReaders after calling macho.Open from
// go-macho. If the file is not a macho binary, it will attempt to open it as a
// FAT binary and return all valid macho binaries from the FAT file.
// `MaxFileSize` is used to limit the size of the file that is processed.
func MachFile(path string) ([]*MachoReader, error) {
	if len(path) == 0 {
		return nil, errEmptyFilePath
	}

	file, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf(errGetFileStatsFailed, err)
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf(errOpenFileFailed, err)
	}

	if fileInfo.Size() > 2*MaxFileSize {
		return nil, fmt.Errorf(errFileGreaterThan2Gig, err)
	}

	reader, err := macho.Open(path)
	if err == nil {
		return []*MachoReader{{
			File:                file,
			MachoReader:         reader,
			filePath:            path,
			ByteStream:          []uint{},
			IsFat:               false,
			ExtractedFileHashes: emptyHashes,
			ArchitectureHashes:  emptyHashes,
			isTempFile:          false,
		}}, nil
	}

	e := fmt.Sprintf("%+v", err)
	WarningLogger.Printf(errFailedToParseMacho, e)

	if !strings.Contains(e, invalidMagic) {
		return nil, fmt.Errorf(errParseMachOFailed, path)
	}

	InfoLogger.Println(infoMachoBeginOpen)

	fatFile, err := macho.NewFatFile(file)
	if err != nil {
		return nil, err
	}

	var readers []*MachoReader
	for _, mg := range fatFile.Arches {
		archTempFile, archHashes, err := createArchTempFile(mg, path)
		var archPath string
		var archFile *os.File
		var architectureHashes *opb.Hash
		var isTemp bool
		if err != nil {
			WarningLogger.Printf("Failed to create temp file for %s architecture: %v", mg.CPU.String(), err)
			archPath = path // Fallback to original path
			archFile = file // Fallback to original file handle
			architectureHashes = emptyHashes
			isTemp = false
		} else {
			archPath = archTempFile
			architectureHashes = archHashes
			isTemp = true
			// Open the architecture-specific temp file for string extraction
			archFile, err = os.Open(archTempFile)
			if err != nil {
				WarningLogger.Printf("Failed to open temp file for %s architecture: %v", mg.CPU.String(), err)
				archPath = path
				archFile = file
				architectureHashes = emptyHashes
				isTemp = false
			}
		}

		readers = append(readers, &MachoReader{
			File:                archFile,
			MachoReader:         mg.File,
			filePath:            archPath,
			ByteStream:          []uint{},
			IsFat:               true,
			ExtractedFileHashes: emptyHashes, // Will be set by archive processing if applicable
			ArchitectureHashes:  architectureHashes,
			isTempFile:          isTemp,
		})
		// Optional: Log if it's an architecture you haven't seen before
		if mg.CPU != types.CPUAmd64 && mg.CPU != types.CPUArm64 &&
			mg.CPU != types.CPUI386 && mg.CPU != types.CPUArm {
			InfoLogger.Printf("Processing less common architecture: %s", mg.CPU.String())
		}
	}

	if len(readers) == 0 {
		return nil, errNoFATFile
	}

	InfoLogger.Println(infoFileOpened)

	return readers, nil
}

// Close closes the file handle and cleans up temporary files if applicable.
// This should be called when done processing a MachoReader to prevent resource leaks.
func (m *MachoReader) Close() error {
	var err error
	if m.File != nil {
		err = m.File.Close()
	}

	// Clean up temporary architecture file if it exists
	if m.isTempFile && m.filePath != "" {
		if removeErr := os.Remove(m.filePath); removeErr != nil && !os.IsNotExist(removeErr) {
			if err == nil {
				err = removeErr
			}
		}
	}

	return err
}

// NewMachoReader will create a new instance of MachoReader.
// It will attempt to open the file as a macho binary (normal or FAT binary). If that
// fails, it will attempt to open it as an archive and extract the macho binary from the
// archive. If that fails, it will return an error.
func NewMachoReader(path string) ([]*MachoReader, error) {
	machBins, err := MachFile(path)
	if err == nil {
		return machBins, nil
	}

	machBins, err = HandleArchiveFiles(path)
	if err != nil {
		defer func() {
			if cleanErr := CleanUpTemp(outputDir); cleanErr != nil {
				ErrorLogger.Printf(errCleaningTempDir, cleanErr)
			}
		}()
		return nil, err
	}

	defer func() {
		if cleanErr := CleanUpTemp(outputDir); cleanErr != nil {
			ErrorLogger.Printf(errCleaningTempDir, cleanErr)
		}
	}()

	return machBins, nil
}

// MachoCandidateFromArchive returns a list of all the macho binaries in the archive.
type MachoCandidateFromArchive struct {
	Reader *MachoReader
	Err    error
}

// HandleArchiveFiles will attempt to open the file as an archive and extract the macho
// binary from the archive. If that fails, it will return an error.
func HandleArchiveFiles(path string) ([]*MachoReader, error) {
	InfoLogger.Println(infoArchiveBeginOpen)
	// If there is an error or the macho binary is nil
	// We want to give it the chance of identifying if it is an macos archive.
	allPaths, err := AllPaths(path)
	if err != nil {
		return nil, err
	}

	if allPaths == nil {
		return nil, fmt.Errorf(errFileNeitherMachoPackage, path)
	}

	hasPlist := HasPlistPath(allPaths)
	plistPaths := PlistPaths(allPaths)

	if !hasPlist {
		return nil, fmt.Errorf(errNoInfoPlist, path)
	}
	if len(plistPaths) == 0 {
		return nil, fmt.Errorf(errNoInfoPlist, path)
	}
	contentPaths := ContentDirectory(allPaths)
	if len(contentPaths) == 0 {
		return nil, fmt.Errorf(errNoContentPaths, path)
	}

	// Since we have content and info.plist extract archive.
	err = ExtractArchive(path)
	if err != nil {
		return nil, fmt.Errorf(errExtractArchiveFailed, path, err)
	}
	// We are only considering archives that have a CFBundleExecutable in their plist.
	// Since it is deterministic to parse such objects.
	var cfBundles []string
	for _, plistPath := range plistPaths {
		pTree, err := ParsePlist(plistPath)
		if err != nil {
			ErrorLogger.Printf(errParsePlistFailed, err)
			continue
		}
		// In an archived/bundled macos application CFBundleExecutable represents the
		// macho the bundler wants the OS to install.
		cfBundle := pTree["CFBundleExecutable"]
		if cfBundle != nil {
			strBundle := (cfBundle).(string)
			cfBundles = append(cfBundles, strBundle)
		}
	}

	machoCandidates := MachoCandidates(contentPaths)
	var toSelect []string
	for _, candidate := range machoCandidates {
		for _, bundle := range cfBundles {
			if strings.HasSuffix(candidate, bundle) {
				toSelect = append(toSelect, candidate)
			}
		}
	}
	if len(toSelect) == 0 {
		return nil, errNoMachoCandidate
	}

	var machBins []*MachoReader
	for _, candidate := range toSelect {
		// Read file content before MachFile processes it
		fileContent, err := os.ReadFile(candidate)
		if err != nil {
			ErrorLogger.Printf("could not read file content for %s: %v", candidate, err)
			continue
		}

		candidateBins, err := MachFile(candidate)
		if err != nil {
			ErrorLogger.Printf(errParseMachOFailed, candidate)
			continue
		}

		// Calculate hash of the extracted binary from archive
		extractedBinaryHashes, err := getHashes(fileContent)
		if err != nil {
			ErrorLogger.Printf("could not generate hashes for %s: %v", candidate, err)
			extractedBinaryHashes = emptyHashes
		}

		for _, reader := range candidateBins {
			reader.ExtractedFileHashes = extractedBinaryHashes
			InfoLogger.Printf("Archive extraction: generated hash=%s for arch=%s from file %s", reader.ExtractedFileHashes.Sha256, reader.MachoReader.CPU.String(), candidate)
		}

		machBins = append(machBins, candidateBins...)
	}

	return machBins, nil
}

// createArchTempFile creates a temporary file containing the specific architecture's binary data from a FAT binary
// Returns both the temp file path and the hashes of the extracted architecture
func createArchTempFile(arch macho.FatArch, originalPath string) (string, *opb.Hash, error) {
	// Open the original FAT file
	file, err := os.Open(originalPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open FAT file: %v", err)
	}
	defer file.Close()

	tempFile, err := os.CreateTemp("", fmt.Sprintf("katalina_arch_%s_*.bin", arch.CPU.String()))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer tempFile.Close()

	tempPath := tempFile.Name()

	// Seek to the architecture's offset in the FAT file
	_, err = file.Seek(int64(arch.Offset), io.SeekStart)
	if err != nil {
		os.Remove(tempPath)
		return "", nil, fmt.Errorf("failed to seek to architecture offset: %v", err)
	}

	// Copy the architecture's binary data to the temp file
	_, err = io.CopyN(tempFile, file, int64(arch.Size))
	if err != nil {
		os.Remove(tempPath)
		return "", nil, fmt.Errorf("failed to copy architecture data: %v", err)
	}

	// Read the extracted file to calculate its hashes
	extractedData, err := os.ReadFile(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return "", nil, fmt.Errorf("failed to read extracted file for hashing: %v", err)
	}

	archHashes, err := getHashes(extractedData)
	if err != nil {
		os.Remove(tempPath)
		return "", nil, fmt.Errorf("failed to calculate hashes for extracted architecture: %v", err)
	}

	InfoLogger.Printf("Created temp file %s for %s architecture (offset: %d, size: %d, hash: %s)",
		tempPath, arch.CPU.String(), arch.Offset, arch.Size, archHashes.Sha256)

	return tempPath, archHashes, nil
}
