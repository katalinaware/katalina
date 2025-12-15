package main

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blacktop/go-macho"
	gm "github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/schollz/progressbar/v3"
	"go.mozilla.org/pkcs7"
	"gonum.org/v1/gonum/stat"

	_ "net/http/pprof"

	opb "github.com/appsworld/katalinaware/protos"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"golang.org/x/crypto/ocsp"
)

type FrameworkCapability int

type ChromeExtensionInfo struct {
	Name        string
	Version     string
	Description string
}

type ChromeExtensionData struct {
	ExtensionId string
	Paths       StringSet
	APIs        StringSet
	RawMatches  StringSet
}

// Categorizing the different MacOS framework capabilities.
// Ref: https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/OSX_Technology_Overview/SystemFrameworks/SystemFrameworks.html
const (
	Security        FrameworkCapability = iota // Security = 0
	AudioVideo                                 // AudioVideo = 1
	Location                                   // Location = 2
	PersonalData                               // PersonalData = 3
	PhysicalVolumes                            // PhysicalVolumes = 4
)

const (
	SHA1   = "sha1"
	SHA256 = "sha256"
	MD5    = "md5"

	pageZeroName = "__PAGEZERO"
	textName     = "__TEXT"
	dataName     = "__DATA"
	linkEditName = "__LINKEDIT"
)

// Code signature magic numbers
const (
	CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0 // SuperBlob magic for embedded signatures
	CSMAGIC_CODEDIRECTORY      = 0xfade0c02 // CodeDirectory blob magic

	// Security limits to prevent resource exhaustion attacks on corrupted binaries.
	// These values are conservative and based on observed Apple code signature patterns.
	// NOTE: If legitimate binaries exceed these limits, consider making them configurable.
	MAX_SUPERBLOB_ENTRIES = 100         // Apple code signatures typically have < 10 entries
	MAX_SUPERBLOB_SIZE    = 1024 * 1024 // 1MB should be sufficient for code signatures
	MAX_CODEDIR_SIZE      = 64 * 1024   // 64KB should be sufficient for a single code directory
)

type gupdate struct {
	App app `xml:"app"`
}

type app struct {
	Status      string      `xml:"status,attr"`
	UpdateCheck updateCheck `xml:"updatecheck"`
}

type updateCheck struct {
	Status  string `xml:"status,attr"`
	Version string `xml:"version,attr"`
}

var (
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
	// If enabled, the binary will not be parsed again.
	skipParsed bool
	// outDir determines the output directory for the parsed results.
	outDir string
	// Debug determines if we should turn on a debug server.
	debug bool
	// allSymbols determines if we should include all the binary symbols in the result file.
	allSymbols bool
	// retAllStrings determines if we should return all the strings found in the result file.
	retAllStrings bool
	generateCFG   bool
	// progresssbar to progress of the parsing process.
	bar *progressbar.ProgressBar
	// chromeExtensionValidationURL is the URL used for validating Chrome extensions.
	chromeExtensionValidationURL = "https://clients2.google.com/service/update2/crx"

	// debugPORT what port to launch the debugger from
	debugPORT = ":8801"
	// execMem is a macOS entitlement that allows an app to execute code from an unsigned region of memory.
	execMem = "com.apple.security.cs.allow-unsigned-executable-memory"
	// taskAllow is typically used in process hollowing.
	taskAllow = "get-task-allow"
	// csJIT allows for runtime privilege escalation.
	csJIT = "com.apple.security.cs.allow-jit"

	// The regex used for the format string below is derived from analyzing
	// https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Strings/Articles/formatSpecifiers.html and
	// https://pubs.opengroup.org/onlinepubs/009695399/functions/printf.html
	reFormatStrings          = regexp.MustCompile(`(?i)%-?(?:(?:\.?\*?\d{0,3}\$?){0,2}(?:l|ll|L|h|hh|j|z|t)?(?:a|A|c|C|d|D|e|E|f|F|g|G|i|o|O|p|s|S|x|X|@))(?:[^\'\"]|$)*`)
	rePlist                  = regexp.MustCompile(`(?i)(~?\/.*\.plist)`)
	rePaths                  = regexp.MustCompile(`(?i)(\/\w+\/[^/]+\/[^/\s]+)`)
	reLaunchAgent            = regexp.MustCompile(`(?i)/library/launchagents`)
	reLaunchDaemon           = regexp.MustCompile(`(?i)/library/launchdaemons`)
	reSQLite                 = regexp.MustCompile(`(?i)INSERT INTO access VALUES`)
	reTCCDb                  = regexp.MustCompile(`(?i)com\.apple].tccd|TCC\.db|active\_policy|kTCCService`)
	reURL                    = regexp.MustCompile(`https?://[^\s]{2,}`)
	reDomain                 = regexp.MustCompile(`(https?://[^\s]{2,}\.\w+)`)
	rePublicKey              = regexp.MustCompile(`-----BEGIN PUBLIC KEY-----`)
	reBase64                 = regexp.MustCompile(`/([A-Za-z0-9+\/]{4}){3,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/`)
	reStartupItems           = regexp.MustCompile(`(?i)/library/startupitems`)
	reScriptingAddition      = regexp.MustCompile(`(?i)(?:(?:/system)?/library/|/applications/.*?/contents/resources/)scripting\s?additions`)
	reLoginWindows           = regexp.MustCompile(`(?i)(com.apple.)?loginwindow.plist`)
	reLoginItems             = regexp.MustCompile(`(?i)com.apple.(loginitems.plist|backgroundtaskmanagementagent/backgrounditems.btm)|loginitems.\d+.plist`)
	reShells                 = regexp.MustCompile(`(?i)((?:/usr)?/bin/(?:bash|fish|ksh|sh|tcsh|zsh))([[:punct:]\s]|$)`)
	reShellStartupFiles      = regexp.MustCompile(`(?i).zshrc|.zprofile|.bashrc|.bash_profile|com.googlecode.iterm2.plist|/library/application support/iterm2/scripts/autolaunch(.scpt)?`)
	reCrontab                = regexp.MustCompile(`(?i)crontab -|(/private)?/etc/crontab|/usr/lib/cron/tabs|/private/var/at/tabs`)
	reSymbolStartingWithAt   = regexp.MustCompile(`(?i)^@(_\w.+)`)
	reIOListening            = regexp.MustCompile(`(?i)(cgeventtapcreate|cgeventtapenable|iohidqueueregistervalueavailablecallback|cgeventgetintegervaluefield|iohiddeviceregisterinputreportcallback)`)
	rePotentialHardwareRecon = regexp.MustCompile(`(?i)(ioethernetinterface|ioservice|ioplatformserialnumber|iomacaddress|iopropertymatch|ioprimaryinterface|ioplatformuuid)`)

	// Information Stealer Detection Patterns
	reKeychainAccess  = regexp.MustCompile(`(?i)\b(chainbreaker|security dump-keychain|keychain-2\.db)\b`)
	reDiscordWebhooks = regexp.MustCompile(`(?i)(discord(app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+)`)

	// macOS Security Bypass Detection Patterns
	reGatekeeperBypass  = regexp.MustCompile(`(?i)\b(spctl\s+--master-disable|spctl\s+--disable|sudo\s+spctl\s+--master-disable|gatekeeper\s+(disable|bypass))\b`)
	reQuarantineRemoval = regexp.MustCompile(`(?i)(xattr\s+-d\s+com\.apple\.quarantine|xattr\s+-c|xattr\s+--delete.*quarantine|removeQuarantine|quarantine.*remove|com\.apple\.quarantine.*delete)`)

	// reSHA256 is a regex to identify potential SHA256 hashes.
	reSHA256 = regexp.MustCompile(`(?i)([a-f0-9]{64})`)

	// Chrome Extension related patterns
	reChromeExtensionId = regexp.MustCompile(`[a-p]{32}`)

	// frameworkCap maps each framework to a capability.
	frameworkCap = map[string]FrameworkCapability{
		// Has Icloud capabilities. Provides a conduit for moving data between your app and iCloud that
		// can be used for all types of data. It also gives you control of when transfers occur.
		"CloudKit.framework": PersonalData,
		// Manages identity information.
		"Collaboration.framework": Security,
		// Provides access to the Contacts store, which is a centralized database of user contact information.
		"Contacts.framework": PersonalData,
		// Provides interfaces for determining the geographical location of a computer.
		"CoreLocation.framework": Location,
		// Provides an interface for accessing a user's calendar events and reminder items.
		"EventKit.framework": PersonalData,
		// Contains Objective-C interfaces for communicating with digital devices such as scanners and cameras.
		"ImageCaptureCore.framework": AudioVideo,
		// Contains the interfaces for Core Image, Core Animation, and Core Video. See Quartz Core Framework Reference.
		"QuartzCore.framework": AudioVideo,
		// Contains interfaces for system-level user authentication and authorization. S
		"Security.framework": Security,
		// Contains Cocoa interfaces for authorizing users.
		"SecurityFoundation.framework": Security,
		// Contains the user interface layer for authorizing users in Cocoa apps
		"SecurityInterface.framework": Security,
		// Provides interfaces for playing, recording, inspecting, and editing audiovisual media. See AVFoundation Audio Functions.
		"AVFoundation.framework": AudioVideo,
		// Provides access to user accounts stored in the Accounts database.
		"Accounts.framework":        Security,
		"DiskArbitration.framework": PhysicalVolumes,
	}

	// resultFile represents the path where we store the results for each processed file.
	resultFile = "result.json"

	errFetchingDYLD  = "error fetching the DyldInfo or DyldInfoOnly command properties"
	errCertNotFound  = errors.New("either the leaf or signer cert could not be found")
	errCreateReq     = errors.New("could not create request")
	errNoOCSPServer  = errors.New("cert cannot be verified via an OCSP server. Might be CRL-based or self-signed")
	errCreateHTTPReq = errors.New("could not create HTTP request")
	errInvalidResp   = errors.New("invalid response from reading HTTP response")

	//go:embed binaries/*
	binaries embed.FS
)

func init() {
	tempDir := os.TempDir()
	logFile := filepath.Join(tempDir, "katalinaware.log")
	fmt.Println("Katalinaware Log file location:", logFile)
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	InfoLogger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	WarningLogger = log.New(file, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	// Manual debug mode - hardcoded values
	// debugFile := "geacon_cobalt_strike/3c220b95852f3bc577d91b1acf7d11cf43d1c87df717470845024a26a705078d"
	// inFile := &debugFile

	// debugDir := "lazarus"
	// inDir := &debugDir

	// outDir = "lazarus"

	skipParsed = false
	debug = true
	allSymbols = true
	retAllStrings = true

	// Command line arguments.
	inFile := flag.String("file", "", "the full path to the file to be parsed. Note, if this is filled, the input_dir will be ignored.")
	inDir := flag.String("input_dir", "", "the full path to the directory holding the files to be parsed")

	flag.StringVar(&outDir, "output_dir", "", "the full path to the directory where the results will be written")
	flag.BoolVar(&skipParsed, "skip_parsed", false, "skip directory already have a result file")
	flag.BoolVar(&debug, "debug", false, "turn on and attach a debug server on port 8801")
	flag.BoolVar(&allSymbols, "all_symbols", false, "include all the binary symbols in the binary")
	flag.BoolVar(&retAllStrings, "all_strings", false, "return all the strings found in the binary")
	flag.BoolVar(&generateCFG, "generate_cfg", false, "generate Control Flow Graphs (expensive operation, significantly impacts performance)")
	maxConcurrency := flag.Int("max_concurrency", 0, "maximum number of files to process concurrently (0 = auto, 1 = sequential)")
	enableProfile := flag.Bool("profile", false, "enable pprof profiling server on :6060")
	cpuProfile := flag.String("cpuprofile", "", "write cpu profile to file")
	memProfile := flag.String("memprofile", "", "write memory profile to file")
	traceFile := flag.String("trace", "", "write execution trace to file")

	flag.Parse()

	if debug {
		go func() {
			_ = http.ListenAndServe(debugPORT, nil)
		}()
	}

	if *enableProfile {
		go func() {
			InfoLogger.Println("Starting pprof server on :6060")
			_ = http.ListenAndServe(":6060", nil)
		}()
	}

	// CPU profiling
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			ErrorLogger.Fatal(err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			ErrorLogger.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}

	// Execution tracing
	if *traceFile != "" {
		f, err := os.Create(*traceFile)
		if err != nil {
			ErrorLogger.Fatal(err)
		}
		defer f.Close()
		if err := trace.Start(f); err != nil {
			ErrorLogger.Fatal(err)
		}
		defer trace.Stop()
	}

	// Memory profiling setup (will be written at the end)
	defer func() {
		if *memProfile != "" {
			f, err := os.Create(*memProfile)
			if err != nil {
				ErrorLogger.Printf("Could not create memory profile: %v", err)
				return
			}
			defer f.Close()
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				ErrorLogger.Printf("Could not write memory profile: %v", err)
			}
		}
	}()

	if outDir != "" {
		if _, err := os.Stat(outDir); os.IsNotExist(err) {
			err := os.Mkdir(outDir, 0777)
			if err != nil {
				ErrorLogger.Printf("could not create output directory %s: %v", outDir, err)
				return // Exit the program.
			}
		}

		if skipParsed {
			// If the directory already has a result file skip it.
			files, err := os.ReadDir(outDir)
			if err != nil {
				ErrorLogger.Printf("could not read output directory %s: %v", outDir, err)
				return
			}
			for _, file := range files {
				// Skip file name with the default result.json or those that are named with SHA256.
				if strings.Contains(file.Name(), resultFile) || (reSHA256.MatchString(file.Name()) && strings.HasSuffix(file.Name(), ".json")) {
					fmt.Printf("Skipping parsed dir: %s.\n  If you want to parse this dir, remove the --skip_parsed option.\n", outDir)
					WarningLogger.Printf("skipping parsed dir: %s", outDir)
					return
				}
			}
		}
	}

	switch {
	case *inFile == "" && *inDir == "":
		ErrorLogger.Println("error: no input directory or file provided")
		// Print the options so user can see what options exists.
		getOptions()
	case *inFile != "":
		// Default to current directory.
		d, err := os.Getwd()
		if err != nil {
			ErrorLogger.Println("Error getting current working directory:", err)
			d = "./"
		}

		if outDir != "" {
			d = outDir
		}
		err = fileParse(d, *inFile)
		if err != nil {
			ErrorLogger.Println(err)
		}
	default:
		dirs, err := os.ReadDir(*inDir)
		if err != nil {
			ErrorLogger.Printf("reading directory %s: %v", *inDir, err)
		}
		if len(dirs) == 0 {
			WarningLogger.Printf("no files found in %s", *inDir)
		}

		// Collect all files first
		var filesToProcess []string
		err = filepath.WalkDir(*inDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				filesToProcess = append(filesToProcess, path)
			}
			return nil
		})
		if err != nil {
			ErrorLogger.Printf("Error collecting files: %v", err)
		}

		InfoLogger.Printf("Found %d files to process", len(filesToProcess))
		bar = progressbar.Default(int64(len(filesToProcess)))

		// Process files concurrently
		err = processFilesConcurrent(filesToProcess, *maxConcurrency)
		if err != nil {
			ErrorLogger.Printf("Concurrent processing error: %v", err)
		}
		bar.Finish()
	}
}

// getOptions prints the usage information for the command line arguments.
func getOptions() {
	info := `Usage: ./katalinaware [options]... FILE]...
	Parses a directory of files or a single file and extracts features from Mach-O binaries.

	file or input_dir must be provided.
	`
	fmt.Println(info)
	flag.VisitAll(func(f *flag.Flag) {
		fmt.Printf("-%s, --%s: \t%s\n", f.Name, f.Name, f.Usage)
	})
}

// Traverse the directory and parse binary files encountered.
func walkAndParse(s string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	defer func() {
		if err := recover(); err != nil {
			ErrorLogger.Printf("error: could not process %s, panic: %v", s, err)
		}
	}()

	// Skip directories and process only files.
	if d.IsDir() {
		bar.Add(1)
		return nil
	}

	if err = bar.Add(1); err != nil {
		ErrorLogger.Println("error: couldn't increment progress bar")
	}

	dir, _ := filepath.Split(s)
	if outDir != "" {
		dir = outDir
	}
	err = fileParse(dir, s)
	if err != nil {
		ErrorLogger.Println(err)
	}
	return nil
}

// fileParse parses a single file in a given path.
func fileParse(dir, path string) error {
	if len(path) == 0 || len(dir) == 0 {
		return errors.New("please provide a valid path or directory")
	}
	var data []byte
	var err error

	data, err = os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read the content of the file : %v", path)
	}

	fileHashes, err := getHashes(data)
	if err != nil {
		return fmt.Errorf("could not generate hashes for file %s: %v", path, err)
	}

	InfoLogger.Printf("Parsing file %s (size: %d bytes, hash: %s)", path, len(data), fileHashes.Sha256)

	mp := emptyAnalysisOutput()
	mp.FilePath = path

	machReaders, err := NewMachoReader(path)
	if err != nil {
		InfoLogger.Printf("Could not parse as Mach-O binary, creating minimal analysis for file %s: %v", path, err)
		mp.ProcessedFileHashes = fileHashes
		mp.FileLineage = []*opb.FileLineageStep{
			{
				Step:        0,
				Description: getOriginalFileDescription(path),
				FilePath:    path,
				Hashes:      fileHashes,
			},
		}
		jsonOptions := protojson.MarshalOptions{
			Indent:          "    ",
			Multiline:       true,
			UseProtoNames:   false,
			EmitUnpopulated: true,
		}
		jsonRepresentation, jsonErr := jsonOptions.Marshal(mp)
		if jsonErr != nil {
			return fmt.Errorf("could not marshal empty file analysis: %v", jsonErr)
		}
		outputFileName := fileHashes.Sha256 + ".json"
		outPath := filepath.Join(dir, outputFileName)
		writeErr := os.WriteFile(outPath, jsonRepresentation, 0644)
		if writeErr != nil {
			return fmt.Errorf("could not write empty file analysis: %v", writeErr)
		}

		InfoLogger.Printf("Empty/non-Mach-O file analysis written to %s", outPath)
		fmt.Printf("%s (empty/non-Mach-O) analysis extracted to %s.\n", path, outPath)
		return nil
	}

	InfoLogger.Printf("Starting to process %d machReaders", len(machReaders))

	// Ensure cleanup of MachoReader resources (file handles and temp files)
	defer func() {
		for i, r := range machReaders {
			if r != nil {
				if err := r.Close(); err != nil {
					ErrorLogger.Printf("Failed to close machReader #%d: %v", i, err)
				}
			}
		}
	}()

	// Use concurrent processing for multiple binaries
	if len(machReaders) > 1 {
		return processMachReadersConcurrent(machReaders, path, fileHashes, dir)
	}

	// Single binary - use sequential processing
	for i, r := range machReaders {
		InfoLogger.Printf("=== Processing machReader #%d ===", i)
		if r == nil || r.File == nil {
			ErrorLogger.Printf("could not proceed because macho reader #%d  is nil", i)
			InfoLogger.Printf("machReader #%d: SKIPPED (nil)", i)
			continue
		}

		// Use the hash of the actual binary being processed for filename generation
		var binaryHash string
		if r.IsFat && r.ArchitectureHashes != nil && r.ArchitectureHashes.Sha256 != "" {
			InfoLogger.Printf("machReader #%d: Using ArchitectureHashes.Sha256=%s, arch=%s, isFat=%v", i, r.ArchitectureHashes.Sha256, r.MachoReader.CPU.String(), r.IsFat)
			binaryHash = r.ArchitectureHashes.Sha256 + "_" + r.MachoReader.CPU.String()
		} else if r.ExtractedFileHashes != nil && r.ExtractedFileHashes.Sha256 != "" {
			InfoLogger.Printf("machReader #%d: Using ExtractedFileHashes.Sha256=%s, arch=%s, isFat=%v", i, r.ExtractedFileHashes.Sha256, r.MachoReader.CPU.String(), r.IsFat)
			binaryHash = r.ExtractedFileHashes.Sha256
		} else {
			InfoLogger.Printf("machReader #%d: Using fileHashes.Sha256=%s, arch=%s, isFat=%v (no extracted hashes)", i, fileHashes.Sha256, r.MachoReader.CPU.String(), r.IsFat)
			if r.IsFat && r.MachoReader.CPU != 0 {
				binaryHash = fileHashes.Sha256 + "_" + r.MachoReader.CPU.String()
			} else {
				binaryHash = fileHashes.Sha256
			}
		}

		InfoLogger.Printf("machReader #%d: PROCESSING (hash: %s, arch: %s)", i, binaryHash, r.MachoReader.CPU.String())

		mp.IsFat = r.IsFat

		mp.ProcessedFileHashes = getProcessedFileHashes(r, fileHashes)
		mp.FileLineage = createFileLineage(path, fileHashes, r)

		mp.MachoHeader = getFileHeader(r)

		ents, err := getEntitlement(r)
		if err != nil {
			ErrorLogger.Printf("could not extract code directory: %v", err)
		}

		buildInformation := BuildInformation(r)
		// Only macOS binaries are supported for full feature extraction.
		// Skip others with a warning.
		if buildInformation.Platform != types.Platform_macOS {
			ErrorLogger.Printf("unsupported platform: %v", buildInformation.Platform.String())
			return fmt.Errorf("unsupported platform: %v", buildInformation.Platform.String())
		}
		mp.ModelFeat.Entitlements = ents
		mp.ModelFeat.CodeDirectory = getCodeDirectory(r)
		mp.ModelFeat.CertFeatures, mp.NonModelFeat.Certificates = getCodeSigning(r)
		mp.ModelFeat.ObjectiveCFeatures = getClasses(r)
		mp.ModelFeat.SwiftFeatures = getSwiftClasses(r)
		mp.NonModelFeat.SymbolInfo = fetchSymbols(r, allSymbols)
		mp.NonModelFeat.Uuid = teamUUID(r)
		mp.ModelFeat.SectionFeatures = getSectionFeatures(r)
		mp.ModelFeat.SegmentFeatures = getSegmentFeatures(r)
		mp.ModelFeat.DylibFeatures = getDyLibFeatures(r)
		mp.ModelFeat.DySymTabFeatures = getDySymTabFeatures(r)
		mp.ModelFeat.DyldInfo = getDyldFeatures(r)

		mp.ModelFeat.ByteEntropyDist = byteDistribution(r)
		mp.ModelFeat.AssemblyFeatures = DisasFeats(r)

		mp.NonModelFeat.RawStringFeat, mp.ModelFeat.Strings = getStringsFeatures(r, []string{})

		jsonOptions := protojson.MarshalOptions{
			Indent:          "    ",
			Multiline:       true,
			UseProtoNames:   false,
			EmitUnpopulated: true,
		}
		jsonRepresentation, err := jsonOptions.Marshal(mp)
		if err != nil {
			return err
		}

		// Use the unique binaryHash for the filename to ensure no overwrites
		resultFile = binaryHash + ".json"

		outPath := filepath.Join(dir, resultFile)
		err = os.WriteFile(outPath, jsonRepresentation, 0644)
		if err != nil {
			return err
		}
		fmt.Printf("%s extracted to %s.\n", path, outPath)
		InfoLogger.Printf("machReader #%d: COMPLETED -> %s", i, outPath)

	}

	return nil
}

// MachReaderJob represents a single machReader processing job
type MachReaderJob struct {
	Index      int
	Reader     *MachoReader
	Path       string
	FileHashes *opb.Hash
	OutputDir  string
}

// MachReaderResult represents the result of processing a machReader
type MachReaderResult struct {
	Index    int
	Error    error
	Success  bool
	FilePath string
}

// processMachReadersConcurrent processes multiple architecture readers from a universal binary concurrently.
// Uses resource-aware worker pools to prevent system overload while maximizing throughput.
func processMachReadersConcurrent(machReaders []*MachoReader, path string, fileHashes *opb.Hash, dir string) error {
	numReaders := len(machReaders)
	numWorkers := min(runtime.NumCPU(), numReaders)

	InfoLogger.Printf("Using %d concurrent workers for %d machReaders", numWorkers, numReaders)

	jobs := make(chan MachReaderJob, numReaders)
	results := make(chan MachReaderResult, numReaders)

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go machReaderWorker(w, jobs, results, &wg)
	}

	go func() {
		defer close(jobs)
		for i, r := range machReaders {
			jobs <- MachReaderJob{
				Index:      i,
				Reader:     r,
				Path:       path,
				FileHashes: fileHashes,
				OutputDir:  dir,
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var errors []error
	processedCount := 0
	for result := range results {
		processedCount++
		if result.Error != nil {
			errors = append(errors, fmt.Errorf("machReader #%d: %v", result.Index, result.Error))
			ErrorLogger.Printf("machReader #%d failed: %v", result.Index, result.Error)
		} else {
			InfoLogger.Printf("machReader #%d: COMPLETED -> %s", result.Index, result.FilePath)
		}
	}

	InfoLogger.Printf("Concurrent processing completed: %d/%d successful", processedCount-len(errors), processedCount)

	if len(errors) > 0 {
		for _, err := range errors {
			ErrorLogger.Printf("Processing error: %v", err)
		}
		return errors[0]
	}

	return nil
}

// machReaderWorker processes architecture-specific analysis jobs from the job channel.
func machReaderWorker(id int, jobs <-chan MachReaderJob, results chan<- MachReaderResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		InfoLogger.Printf("Worker %d: Processing machReader #%d", id, job.Index)

		result := MachReaderResult{
			Index: job.Index,
		}

		filePath, err := processSingleMachReader(job.Index, job.Reader, job.Path, job.FileHashes, job.OutputDir)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Success = true
			result.FilePath = filePath
			fmt.Printf("%s extracted to %s.\n", job.Path, filePath)
		}

		results <- result
	}
}

// processSingleMachReader performs complete feature extraction and analysis for a single architecture.
// This function encapsulates all processing steps from hash generation to final JSON output.
func processSingleMachReader(index int, r *MachoReader, path string, fileHashes *opb.Hash, dir string) (string, error) {
	InfoLogger.Printf("=== Processing machReader #%d ===", index)

	if r == nil || r.File == nil {
		ErrorLogger.Printf("could not proceed because macho reader #%d is nil", index)
		InfoLogger.Printf("machReader #%d: SKIPPED (nil)", index)
		return "", fmt.Errorf("machReader #%d is nil", index)
	}

	// Use the hash of the actual binary being processed for filename generation
	var binaryHash string
	if r.IsFat && r.ArchitectureHashes != nil && r.ArchitectureHashes.Sha256 != "" {
		InfoLogger.Printf("machReader #%d: Using ArchitectureHashes.Sha256=%s, arch=%s, isFat=%v", index, r.ArchitectureHashes.Sha256, r.MachoReader.CPU.String(), r.IsFat)
		binaryHash = r.ArchitectureHashes.Sha256 + "_" + r.MachoReader.CPU.String()
	} else if r.ExtractedFileHashes != nil && r.ExtractedFileHashes.Sha256 != "" {
		InfoLogger.Printf("machReader #%d: Using ExtractedFileHashes.Sha256=%s, arch=%s, isFat=%v", index, r.ExtractedFileHashes.Sha256, r.MachoReader.CPU.String(), r.IsFat)
		binaryHash = r.ExtractedFileHashes.Sha256
	} else {
		InfoLogger.Printf("machReader #%d: Using fileHashes.Sha256=%s, arch=%s, isFat=%v (no extracted hashes)", index, fileHashes.Sha256, r.MachoReader.CPU.String(), r.IsFat)
		if r.IsFat && r.MachoReader.CPU != 0 {
			binaryHash = fileHashes.Sha256 + "_" + r.MachoReader.CPU.String()
		} else {
			binaryHash = fileHashes.Sha256
		}
	}

	InfoLogger.Printf("machReader #%d: PROCESSING (hash: %s, arch: %s)", index, binaryHash, r.MachoReader.CPU.String())

	// Create a new AnalysisOutput instance for this reader
	start := time.Now()
	mp := emptyAnalysisOutput()
	InfoLogger.Printf("machReader #%d: emptyAnalysisOutput took %v", index, time.Since(start))
	mp.FilePath = path
	mp.IsFat = r.IsFat

	start = time.Now()
	mp.ProcessedFileHashes = getProcessedFileHashes(r, fileHashes)
	InfoLogger.Printf("machReader #%d: getProcessedFileHashes took %v", index, time.Since(start))

	start = time.Now()
	mp.FileLineage = createFileLineage(path, fileHashes, r)
	InfoLogger.Printf("machReader #%d: createFileLineage took %v", index, time.Since(start))

	// Extract all features (this is the expensive part)
	start = time.Now()
	mp.MachoHeader = getFileHeader(r)
	InfoLogger.Printf("machReader #%d: getFileHeader took %v", index, time.Since(start))

	start = time.Now()
	ents, err := getEntitlement(r)
	if err != nil {
		ErrorLogger.Printf("could not extract code directory: %v", err)
	}
	mp.ModelFeat.Entitlements = ents
	InfoLogger.Printf("machReader #%d: getEntitlement took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.CodeDirectory = getCodeDirectory(r)
	InfoLogger.Printf("machReader #%d: getCodeDirectory took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.CertFeatures, mp.NonModelFeat.Certificates = getCodeSigning(r)
	InfoLogger.Printf("machReader #%d: getCodeSigning took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.ObjectiveCFeatures = getClasses(r)
	InfoLogger.Printf("machReader #%d: getClasses took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.SwiftFeatures = getSwiftClasses(r)
	InfoLogger.Printf("machReader #%d: getSwiftClasses took %v", index, time.Since(start))

	start = time.Now()
	mp.NonModelFeat.SymbolInfo = fetchSymbols(r, allSymbols)
	InfoLogger.Printf("machReader #%d: fetchSymbols took %v", index, time.Since(start))

	start = time.Now()
	mp.NonModelFeat.Uuid = teamUUID(r)
	InfoLogger.Printf("machReader #%d: teamUUID took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.SectionFeatures = getSectionFeatures(r)
	InfoLogger.Printf("machReader #%d: getSectionFeatures took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.SegmentFeatures = getSegmentFeatures(r)
	InfoLogger.Printf("machReader #%d: getSegmentFeatures took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.DylibFeatures = getDyLibFeatures(r)
	InfoLogger.Printf("machReader #%d: getDyLibFeatures took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.DySymTabFeatures = getDySymTabFeatures(r)
	InfoLogger.Printf("machReader #%d: getDySymTabFeatures took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.DyldInfo = getDyldFeatures(r)
	InfoLogger.Printf("machReader #%d: getDyldFeatures took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.ByteEntropyDist = byteDistribution(r)
	InfoLogger.Printf("machReader #%d: byteDistribution took %v", index, time.Since(start))

	start = time.Now()
	mp.ModelFeat.AssemblyFeatures = DisasFeats(r)
	InfoLogger.Printf("machReader #%d: DisasFeats took %v", index, time.Since(start))

	start = time.Now()
	mp.NonModelFeat.RawStringFeat, mp.ModelFeat.Strings = getStringsFeatures(r, []string{})
	InfoLogger.Printf("machReader #%d: getStringsFeatures took %v", index, time.Since(start))

	// Use protojson for marshalling
	jsonOptions := protojson.MarshalOptions{
		Indent:          "    ",
		Multiline:       true,
		UseProtoNames:   false,
		EmitUnpopulated: true,
	}
	jsonRepresentation, err := jsonOptions.Marshal(mp)
	if err != nil {
		return "", fmt.Errorf("could not marshal JSON: %v", err)
	}

	resultFile := binaryHash + ".json"
	outPath := filepath.Join(dir, resultFile)
	err = os.WriteFile(outPath, jsonRepresentation, 0644)
	if err != nil {
		return "", fmt.Errorf("could not write file: %v", err)
	}

	return outPath, nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FileJob represents a single file processing job
type FileJob struct {
	FilePath string
}

// FileResult represents the result of processing a file
type FileResult struct {
	FilePath string
	Error    error
	Success  bool
}

// processFilesConcurrent processes multiple files in parallel using a worker pool pattern.
// Automatically scales worker count based on CPU cores while respecting I/O constraints.
func processFilesConcurrent(filePaths []string, maxConcurrency int) error {
	if len(filePaths) == 0 {
		return nil
	}

	var numWorkers int
	if maxConcurrency > 0 {
		numWorkers = min(maxConcurrency, len(filePaths))
	} else {
		numWorkers = min(runtime.NumCPU()*2, len(filePaths))
		if numWorkers > 8 {
			numWorkers = 8
		}
	}

	InfoLogger.Printf("Using %d concurrent workers for %d files", numWorkers, len(filePaths))

	jobs := make(chan FileJob, len(filePaths))
	results := make(chan FileResult, len(filePaths))

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go fileWorker(w, jobs, results, &wg)
	}

	// Send jobs to workers
	go func() {
		defer close(jobs)
		for _, filePath := range filePaths {
			jobs <- FileJob{FilePath: filePath}
		}
	}()

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and update progress
	var errors []error
	processedCount := 0
	for result := range results {
		processedCount++
		bar.Add(1) // Update progress bar

		if result.Error != nil {
			errors = append(errors, fmt.Errorf("file %s: %v", result.FilePath, result.Error))
			ErrorLogger.Printf("File processing failed: %s -> %v", result.FilePath, result.Error)
		} else {
			InfoLogger.Printf("File processing completed: %s", result.FilePath)
		}
	}

	InfoLogger.Printf("Concurrent file processing completed: %d/%d successful", processedCount-len(errors), processedCount)

	// Log errors but don't fail completely (graceful degradation)
	for _, err := range errors {
		ErrorLogger.Printf("Processing error: %v", err)
	}

	return nil
}

// fileWorker processes file jobs from the job channel
func fileWorker(id int, jobs <-chan FileJob, results chan<- FileResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		InfoLogger.Printf("Worker %d: Processing file %s", id, job.FilePath)

		result := FileResult{
			FilePath: job.FilePath,
		}

		// Process the file using the existing walkAndParse logic
		err := processFileForConcurrency(job.FilePath)
		if err != nil {
			result.Error = err
			result.Success = false
		} else {
			result.Success = true
		}

		results <- result
	}
}

// processFileForConcurrency adapts the walkAndParse logic for concurrent processing
func processFileForConcurrency(filePath string) error {
	// Recreate the walkAndParse logic for a single file
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("could not stat file: %v", err)
	}

	// Skip directories (shouldn't happen but be safe)
	if fileInfo.IsDir() {
		return nil
	}

	// Process the file
	err = fileParse(outDir, filePath)
	if err != nil {
		return fmt.Errorf("could not parse file: %v", err)
	}

	return nil
}

// getFileHeader extracts the file header features from the macho file.
func getFileHeader(mR *MachoReader) *opb.MachoHeader {
	var flags []string
	if mR == nil || mR.MachoReader == nil {
		return &opb.MachoHeader{
			Magic:          "",
			CpuType:        "",
			CpuSubType:     "",
			HeaderFileType: "",
			NumCmds:        0,
			CmdSize:        0,
			Flags:          []string{},
			NumFlags:       0,
		}
	}

	fHeader := mR.MachoReader.FileHeader
	if isFileHeaderEmpty(fHeader) {
		ErrorLogger.Println("error: file header is empty, we are cannot process the file")
		return &opb.MachoHeader{
			Magic:          "",
			CpuType:        "",
			CpuSubType:     "",
			HeaderFileType: "",
			NumCmds:        0,
			CmdSize:        0,
			Flags:          []string{},
			NumFlags:       0,
		}
	}
	f := fHeader.Flags.Flags()
	if len(f) > 0 && f[0] != "None" {
		flags = f
	}

	return &opb.MachoHeader{
		Magic:          fHeader.Magic.String(),
		CpuType:        fHeader.CPU.String(),
		CpuSubType:     fHeader.SubCPU.Capabilities(fHeader.CPU),
		NumCmds:        int32(fHeader.NCommands),
		Flags:          flags,
		CmdSize:        int32(fHeader.SizeCommands),
		NumFlags:       int32(len(flags)),
		HeaderFileType: fHeader.Type.String(),
	}
}

// isFileHeaderEmpty checks if a Mach-O file header contains default/empty values.
// Returns true if all critical header fields are zero or uninitialized.
func isFileHeaderEmpty(fH types.FileHeader) bool {
	return fH.Magic == 0 &&
		fH.NCommands == 0 &&
		fH.SizeCommands == 0 &&
		len(fH.Flags.Flags()) == 0
}

// getCodeDirectory extracts the code directory features from the macho file.
func getCodeDirectory(mR *MachoReader) *opb.CodeDirectory {
	codeSignature := getCodeSignature(mR)
	if codeSignature == nil {
		return &opb.CodeDirectory{
			Id:     "",
			TeamId: "",
			SpecialSlots: &opb.SpecialSlot{
				PsListHash:       "",
				RequirementsHash: "",
				EntitlementHash:  "",
				CodeResourceHash: "",
			},
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
	}

	var (
		teamIds, Ids StringSet
		specialSlot  = &opb.SpecialSlot{
			PsListHash:       "",
			RequirementsHash: "",
			EntitlementHash:  "",
			CodeResourceHash: "",
		}

		cdRes = &opb.CodeDirectory{
			Id:           "",
			TeamId:       "",
			SpecialSlots: specialSlot,
		}
	)

	teamIds.NewStringSet()
	Ids.NewStringSet()

	// Extract CDHash information first (independent of codeDirectories array)
	populateCDHashInfo(mR, cdRes)

	codeDirectories := codeSignature.CodeDirectories
	for _, cd := range codeDirectories {
		if reflect.TypeOf(cd) == nil {
			continue
		}

		if len(cd.ID) > 0 {
			Ids.Add(cd.ID)
		}

		if len(cd.TeamID) > 0 {
			teamIds.Add(cd.TeamID)
		}

		for _, cs := range cd.SpecialSlots {
			if reflect.TypeOf(cs) == nil {
				continue
			}
			if len(cs.Desc) == 0 || len(cs.Hash) == 0 {
				continue
			}
			desc := cs.Desc
			hashVal := fmt.Sprintf("%x", cs.Hash)
			switch {
			case strings.Contains(desc, "Requirements Blob"):
				specialSlot.RequirementsHash = hashVal
			case strings.Contains(desc, "Bound Info.plist"):
				specialSlot.PsListHash = hashVal
			case strings.Contains(desc, "Entitlement"):
				specialSlot.EntitlementHash = hashVal
			case strings.Contains(desc, "Resource"):
				specialSlot.CodeResourceHash = hashVal
			default:
				continue
			}
		}
	}

	// Take the first value from the sets (most common case)
	teamIdList := teamIds.Strings()
	if len(teamIdList) > 0 {
		cdRes.TeamId = teamIdList[0]
	}

	idList := Ids.Strings()
	if len(idList) > 0 {
		cdRes.Id = idList[0]
	}

	return cdRes
}

// populateCDHashInfo extracts and computes code directory hash information from a Mach-O binary.
// It validates SuperBlob structure (magic number, reasonable bounds) to prevent infinite loops
// on corrupted binaries, then searches for valid code directory entries (CSSLOT_CODEDIRECTORY)
// and computes both SHA1 and SHA256 CDHashes from the raw code directory data.
func populateCDHashInfo(mR *MachoReader, cdRes *opb.CodeDirectory) {
	if mR == nil || mR.File == nil || cdRes == nil {
		return
	}

	codeSignCmd := mR.MachoReader.CodeSignature()
	if codeSignCmd == nil {
		return
	}
	file := mR.File

	_, err := file.Seek(int64(codeSignCmd.Offset), io.SeekStart)
	if err != nil {
		return
	}
	var superBlobHeader struct {
		Magic  uint32
		Length uint32
		Count  uint32
	}

	err = binary.Read(file, binary.BigEndian, &superBlobHeader)
	if err != nil {
		return
	}

	if superBlobHeader.Magic != CSMAGIC_EMBEDDED_SIGNATURE {
		return
	}

	if superBlobHeader.Count > MAX_SUPERBLOB_ENTRIES || superBlobHeader.Length > MAX_SUPERBLOB_SIZE {
		return
	}

	for i := uint32(0); i < superBlobHeader.Count; i++ {
		var blobIndex struct {
			Type   uint32
			Offset uint32
		}

		err = binary.Read(file, binary.BigEndian, &blobIndex)
		if err != nil {
			continue
		}

		if blobIndex.Type == 0 || (blobIndex.Type >= 0x1000 && blobIndex.Type < 0x1010) {
			cdOffset := int64(codeSignCmd.Offset + blobIndex.Offset)

			if cdOffset < 0 || uint32(cdOffset) >= codeSignCmd.Offset+codeSignCmd.Size {
				continue
			}

			_, err = file.Seek(cdOffset, io.SeekStart)
			if err != nil {
				continue
			}

			var blobHeader struct {
				Magic  uint32
				Length uint32
			}

			err = binary.Read(file, binary.BigEndian, &blobHeader)
			if err != nil {
				continue
			}

			if blobHeader.Magic != CSMAGIC_CODEDIRECTORY {
				continue
			}

			if blobHeader.Length > MAX_CODEDIR_SIZE || blobHeader.Length == 0 {
				continue
			}

			var cdHeader struct {
				Version       uint32
				Flags         uint32
				HashOffset    uint32
				IdentOffset   uint32
				NSpecialSlots uint32
				NCodeSlots    uint32
				CodeLimit     uint32
				HashSize      uint8
				HashType      uint8
				Platform      uint8
				PageSize      uint8
				Spare2        uint32
			}

			err = binary.Read(file, binary.BigEndian, &cdHeader)
			if err != nil {
				continue
			}

			cdRes.HashType = int32(cdHeader.HashType)
			_, err = file.Seek(cdOffset, io.SeekStart)
			if err != nil {
				continue
			}

			cdData := make([]byte, blobHeader.Length)
			_, err = io.ReadFull(file, cdData)
			if err != nil {
				continue
			}
			sha1Hash := sha1.New()
			sha1Hash.Write(cdData)
			sha1Full := sha1Hash.Sum(nil)
			sha1CDHash := fmt.Sprintf("%x", sha1Full[:20])
			sha1CDHashFull := fmt.Sprintf("%x", sha1Full)

			sha256Hash := sha256.New()
			sha256Hash.Write(cdData)
			sha256Full := sha256Hash.Sum(nil)
			sha256CDHash := fmt.Sprintf("%x", sha256Full[:20])
			sha256CDHashFull := fmt.Sprintf("%x", sha256Full)

			cdRes.ComputedSha1Cdhash = sha1CDHash
			cdRes.ComputedSha1CdhashFull = sha1CDHashFull
			cdRes.ComputedSha256Cdhash = sha256CDHash
			cdRes.ComputedSha256CdhashFull = sha256CDHashFull

			// Populate extracted CDHash based on what the binary actually uses
			switch cdHeader.HashType {
			case 1: // SHA1
				cdRes.ExtractedCdhash = sha1CDHash
				cdRes.ExtractedCdhashFull = sha1CDHashFull
			case 2: // SHA256
				cdRes.ExtractedCdhash = sha256CDHash
				cdRes.ExtractedCdhashFull = sha256CDHashFull
			}

			cdRes.Notarization = checkNotarizationForCDHash(cdRes.ExtractedCdhash)

			return
		}
	}
}

// BuildInformation return the build specific information about a macho
func BuildInformation(mR *MachoReader) types.BuildVersionCmd {
	if mR == nil || mR.MachoReader == nil {
		return types.BuildVersionCmd{}
	}

	for _, l := range mR.MachoReader.Loads {
		if bv, ok := l.(*gm.BuildVersion); ok {
			return bv.BuildVersionCmd
		}
	}
	return types.BuildVersionCmd{}
}

// getCodeSignature extracts the code signing features from the macho file.
func getCodeSignature(mR *MachoReader) *macho.CodeSignature {
	if mR == nil || mR.MachoReader == nil {
		return nil
	}

	if mR.MachoReader.CodeSignature() == nil {
		return nil
	}

	return mR.MachoReader.CodeSignature()
}

// getEntitlement extracts the entitlement features from the macho file.
func getEntitlement(mR *MachoReader) (*opb.Entitlements, error) {
	et := &opb.Entitlements{
		Entitlements:        []string{},
		EntHash:             "",
		PlistHash:           "",
		HasTaskAllow:        false,
		HasAllowUnsignedMem: false,
		HasJitAllow:         false,
	}

	if mR == nil || mR.MachoReader == nil {
		return et, nil
	}

	if mR.MachoReader.CodeSignature() == nil {
		return et, nil
	}

	codeSignature := mR.MachoReader.CodeSignature()

	var err error

	if codeSignature.EntitlementsDER != nil {
		et.EntHash, err = hashObject(codeSignature.EntitlementsDER, "sha256")
		if err != nil {
			ErrorLogger.Printf("could not hash entitlement der cert : %v", err)
		}
	}

	if codeSignature.Entitlements == "" {
		return et, nil

	}
	entitlements := codeSignature.Entitlements

	et.Entitlements, err = getPsLists([]byte(entitlements))
	if err != nil {
		ErrorLogger.Printf("could not parse the entitlement command : %v", err)
	}

	et.PlistHash, err = hashObject([]byte(entitlements), "sha256")
	if err != nil {
		ErrorLogger.Printf("could not hash plist(entitlement) : %v", err)
	}

	if strings.Contains(entitlements, execMem) {
		et.HasAllowUnsignedMem = true
	}

	if strings.Contains(entitlements, taskAllow) {
		et.HasTaskAllow = true
	}

	if strings.Contains(entitlements, csJIT) {
		et.HasJitAllow = true
	}

	return et, err
}

// hashObject hashes the data stream using the specified hash algorithm.
func hashObject(data []byte, hashAlgo string) (string, error) {
	var hashVal hash.Hash
	var err error
	switch hashAlgo {
	case SHA256:
		hashVal = sha256.New()
		_, err = hashVal.Write(data)
	case MD5:
		hashVal = md5.New()
		_, err = hashVal.Write(data)
	case SHA1:
		hashVal = sha1.New()
		_, err = hashVal.Write(data)
	default:
		ErrorLogger.Printf("unsupported hash type : %s", hashAlgo)
		return "", err
	}
	if hashVal.Size() == 0 {
		return "", errors.New("could not generate the digest for the data stream")
	}
	return hex.EncodeToString(hashVal.Sum(nil)), err
}

// getClasses extracts the Objective C related class features from the macho file.
func getClasses(f *MachoReader) *opb.ObjCFeatures {
	objcFeat := &opb.ObjCFeatures{
		MethodNames: []string{},
		MethodHash:  "",
		ClassNames:  []string{},
		ClassHash:   "",
	}
	if !f.MachoReader.HasObjC() {
		return objcFeat
	}

	pathRE := regexp.MustCompile(`[^\d\p{Latin}]`)

	if methods, err := f.MachoReader.GetObjCMethodNames(); err == nil {
		for _, method := range methods {
			method = pathRE.ReplaceAllString(method, "")
			if method == "" {
				continue
			}
			objcFeat.MethodNames = append(objcFeat.MethodNames, method)
		}
	}
	sort.Strings(objcFeat.MethodNames)
	var err error
	if len(objcFeat.MethodNames) > 0 {
		objcFeat.MethodHash, err = hashObject([]byte(strings.Join(objcFeat.MethodNames, ",")), SHA256)
		if err != nil {
			ErrorLogger.Print(err)
		}
	}

	if classes, err := f.MachoReader.GetObjCClassNames(); err == nil {
		for _, class := range classes {
			class = pathRE.ReplaceAllString(class, "")
			if class == "" {
				continue
			}
			objcFeat.ClassNames = append(objcFeat.ClassNames, class)
		}
	}
	sort.Strings(objcFeat.ClassNames)
	if len(objcFeat.ClassNames) > 0 {
		objcFeat.ClassHash, err = hashObject([]byte(strings.Join(objcFeat.ClassNames, ",")), SHA256)
		if err != nil {
			ErrorLogger.Print(err)
		}
	}

	return objcFeat
}

// getSwiftClasses extracts the Swift related type features from the macho file.
func getSwiftClasses(f *MachoReader) *opb.SwiftFeatures {
	swiftFeat := &opb.SwiftFeatures{
		TypeNames: []string{},
		TypeHash:  "",
	}
	if f.MachoReader == nil || !f.MachoReader.HasSwift() {
		return swiftFeat
	}

	pathRE := regexp.MustCompile(`[^\d\p{Latin}]`)

	// Extract Swift types
	if types, err := f.MachoReader.GetSwiftTypes(); err == nil {
		typeNames := make(map[string]bool)
		for _, swiftType := range types {
			if swiftType.Name != "" {
				name := pathRE.ReplaceAllString(swiftType.Name, "")
				if name != "" && !typeNames[name] {
					typeNames[name] = true
					swiftFeat.TypeNames = append(swiftFeat.TypeNames, name)
				}
			}
		}
	}

	// Only calculate hash for TypeNames since we're only populating types for now
	sort.Strings(swiftFeat.TypeNames)
	if len(swiftFeat.TypeNames) > 0 {
		var err error
		swiftFeat.TypeHash, err = hashObject([]byte(strings.Join(swiftFeat.TypeNames, ",")), SHA256)
		if err != nil {
			ErrorLogger.Print(err)
		}
	}

	return swiftFeat
}

// StringPattern defines a regex pattern for string extraction with optional validation.
// CountOnly patterns save memory by only tracking counts without storing matches.
type StringPattern struct {
	Name       string
	Regex      *regexp.Regexp
	ValidateFn func(string) bool
	CountOnly  bool
}

// StringPatternResult holds the results for a specific pattern
type StringPatternResult struct {
	Matches StringSet
	Count   int32
}

// StringProcessingResult holds the results of processing a batch of strings in parallel
type StringProcessingResult struct {
	LenSum         int
	Lengths        []int
	MaxLength      int32
	PatternResults map[string]*StringPatternResult
	NumCerts       int32
	NumBase64      int32
}

// getStringPatterns returns all configured regex patterns for string extraction.
// This centralizes pattern definitions for maintainability and allows easy modification
// of validation rules and count-only behaviors.
func getStringPatterns() []*StringPattern {
	return []*StringPattern{
		{
			Name:       "urls",
			Regex:      reURL,
			ValidateFn: nil,
			CountOnly:  false,
		},
		{
			Name:       "urlsWithFormatString",
			Regex:      reURL,
			ValidateFn: func(s string) bool { return reFormatStrings.MatchString(s) },
			CountOnly:  false,
		},
		{
			Name:       "paths",
			Regex:      rePaths,
			ValidateFn: isValidPath,
			CountOnly:  false,
		},
		{
			Name:       "pathsWithFormatString",
			Regex:      rePaths,
			ValidateFn: func(s string) bool { return isValidPath(s) && reFormatStrings.MatchString(s) },
			CountOnly:  false,
		},
		{
			Name:       "plistPaths",
			Regex:      rePlist,
			ValidateFn: isValidPath,
			CountOnly:  false,
		},
		{
			Name:       "shells",
			Regex:      reShells,
			ValidateFn: nil,
			CountOnly:  false,
		},
		{
			Name:       "ioListeners",
			Regex:      reIOListening,
			ValidateFn: nil,
			CountOnly:  false,
		},
		{
			Name:       "hwRecon",
			Regex:      rePotentialHardwareRecon,
			ValidateFn: nil,
			CountOnly:  false,
		},
		{
			Name:       "atSymbols",
			Regex:      reSymbolStartingWithAt,
			ValidateFn: nil,
			CountOnly:  false,
		},
		{
			Name:       "chromeExtensions",
			Regex:      reChromeExtensionId,
			ValidateFn: nil,
			CountOnly:  false,
		},
		{
			Name:       "publicKeys",
			Regex:      rePublicKey,
			ValidateFn: nil,
			CountOnly:  true,
		},
		{
			Name:  "base64",
			Regex: reBase64,
			ValidateFn: func(s string) bool {
				if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
					return isASCII(decoded)
				}
				return false
			},
			CountOnly: true,
		},
	}
}

// processStringsParallel processes strings concurrently using worker goroutines.
// Each worker applies all configured patterns to its assigned string batch.
// Results are collected and aggregated by pattern type for efficient processing.
func processStringsParallel(strings []string, numWorkers int) []*StringProcessingResult {
	if len(strings) == 0 {
		return nil
	}

	patterns := getStringPatterns()
	chunkSize := len(strings) / numWorkers
	if chunkSize == 0 {
		chunkSize = 1
		numWorkers = len(strings)
	}

	results := make([]*StringProcessingResult, numWorkers)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			start := workerID * chunkSize
			end := start + chunkSize
			if workerID == numWorkers-1 {
				end = len(strings)
			}

			result := &StringProcessingResult{
				MaxLength:      0,
				PatternResults: make(map[string]*StringPatternResult),
			}

			for _, pattern := range patterns {
				result.PatternResults[pattern.Name] = &StringPatternResult{
					Count: 0,
				}
				if !pattern.CountOnly {
					result.PatternResults[pattern.Name].Matches.NewStringSet()
				}
			}

			for j := start; j < end; j++ {
				matchString := strings[j]
				l := len(matchString)
				result.LenSum += l
				result.Lengths = append(result.Lengths, l)

				if int32(l) > result.MaxLength {
					result.MaxLength = int32(l)
				}

				for _, pattern := range patterns {
					matches := pattern.Regex.FindAllString(matchString, -1)
					patternResult := result.PatternResults[pattern.Name]

					for _, match := range matches {
						if pattern.ValidateFn != nil && !pattern.ValidateFn(match) {
							continue
						}

						patternResult.Count++

						if !pattern.CountOnly {
							patternResult.Matches.Add(match)
						}
					}

					if pattern.Name == "publicKeys" {
						result.NumCerts += patternResult.Count
					} else if pattern.Name == "base64" {
						result.NumBase64 += patternResult.Count
					}
				}
			}

			results[workerID] = result
		}(i)
	}

	wg.Wait()
	return results
}

// getStringPatternByName retrieves a pattern configuration by name.
func getStringPatternByName(name string) *StringPattern {
	patterns := getStringPatterns()
	for _, pattern := range patterns {
		if pattern.Name == name {
			return pattern
		}
	}
	return &StringPattern{CountOnly: false}
}

// getStringsFeatures extracts and analyzes string patterns from Mach-O binaries.
// Uses parallel processing and pattern-based extraction for performance.
// Limits processing to 50k strings for very large binaries to prevent resource exhaustion.
func getStringsFeatures(r *MachoReader, symbols []string) (*opb.RawStringFeat, *opb.StringModel) {
	var (
		lenSum               int
		lengths              []int
		domains              StringSet
		consolidatedPatterns = make(map[string]*StringSet)

		stringFeat = &opb.RawStringFeat{
			AllStrings:               "",
			PathsBestEffort:          make([]string, 0),
			UniquePlistPaths:         make([]string, 0),
			PathsWithFString:         make([]string, 0),
			UrlWithFString:           make([]string, 0),
			UniqueDomains:            make([]string, 0),
			UrlBestEffort:            make([]string, 0),
			UniqueShells:             make([]string, 0),
			UniqueIoDeviceListeners:  make([]string, 0),
			UniquePotentialHwRecon:   make([]string, 0),
			UniqueSymbolsWithAt:      make([]string, 0),
			ChromeExtensions:         make([]*opb.ChromeExtensionValidation, 0),
			MatchedKeychainAccess:    make([]string, 0),
			MatchedDiscordWebhooks:   make([]string, 0),
			MatchedGatekeeperBypass:  make([]string, 0),
			MatchedQuarantineRemoval: make([]string, 0),
		}
		modelString = &opb.StringModel{
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
		}
	)

	patternNames := []string{"urls", "urlsWithFormatString", "paths", "pathsWithFormatString",
		"plistPaths", "shells", "ioListeners", "hwRecon", "atSymbols", "chromeExtensions",
		"keychainAccess", "discordWebhooks", "gatekeeperBypass", "quarantineRemoval"}
	for _, name := range patternNames {
		var s StringSet
		s.NewStringSet()
		consolidatedPatterns[name] = &s
	}

	rawStrings, err := stringFromFile(r.File)
	if err != nil {
		ErrorLogger.Println("error retrieving strings from file:", err)
		rawStrings = []string{}
	}

	rawStrings = append(rawStrings, symbols...)

	strs := allStrings(r)
	strs.Add(symbols...)

	processedStrings := strs.Strings()
	stringsLen := int32(len(processedStrings))

	maxStringsToProcess := 50000
	if len(processedStrings) > maxStringsToProcess {
		processedStrings = processedStrings[:maxStringsToProcess]
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}

	results := processStringsParallel(processedStrings, numWorkers)

	for _, result := range results {
		lenSum += result.LenSum
		lengths = append(lengths, result.Lengths...)

		for patternName, patternResult := range result.PatternResults {
			if patternResult != nil && !getStringPatternByName(patternName).CountOnly {
				consolidatedPatterns[patternName].Add(patternResult.Matches.Strings()...)
			}
		}

		modelString.Encodings.NumCerts += result.NumCerts
		modelString.Encodings.NumBase64 += result.NumBase64

		if result.MaxLength > modelString.MaxLength {
			modelString.MaxLength = result.MaxLength
		}
	}
	modelString.NumUrl = int32(consolidatedPatterns["urls"].Len())
	modelString.NumUrlWithFString = int32(consolidatedPatterns["urlsWithFormatString"].Len())
	modelString.NumPaths = int32(consolidatedPatterns["paths"].Len())
	modelString.NumPathWithFString = int32(consolidatedPatterns["pathsWithFormatString"].Len())
	modelString.NumUniquePlistPaths = int32(consolidatedPatterns["plistPaths"].Len())
	modelString.NumUniqueShells = int32(consolidatedPatterns["shells"].Len())
	modelString.NumIoDeviceListeners = int32(consolidatedPatterns["ioListeners"].Len())
	modelString.NumPotentialHwRecon = int32(consolidatedPatterns["hwRecon"].Len())

	for _, matchString := range processedStrings {
		updateFeatures(modelString, matchString, consolidatedPatterns)
	}
	stringFeat.PathsBestEffort = consolidatedPatterns["paths"].Strings()
	stringFeat.UniquePlistPaths = consolidatedPatterns["plistPaths"].Strings()
	stringFeat.PathsWithFString = consolidatedPatterns["pathsWithFormatString"].Strings()
	stringFeat.UrlBestEffort = consolidatedPatterns["urls"].Strings()
	stringFeat.UrlWithFString = consolidatedPatterns["urlsWithFormatString"].Strings()
	stringFeat.UniqueShells = consolidatedPatterns["shells"].Strings()
	stringFeat.UniqueIoDeviceListeners = consolidatedPatterns["ioListeners"].Strings()
	stringFeat.UniquePotentialHwRecon = consolidatedPatterns["hwRecon"].Strings()

	// Information Stealer Detection - Populate matched string fields (only for patterns we kept)
	stringFeat.MatchedKeychainAccess = consolidatedPatterns["keychainAccess"].Strings()
	stringFeat.MatchedDiscordWebhooks = consolidatedPatterns["discordWebhooks"].Strings()

	// macOS Security Bypass Detection - Populate matched string fields
	stringFeat.MatchedGatekeeperBypass = consolidatedPatterns["gatekeeperBypass"].Strings()
	stringFeat.MatchedQuarantineRemoval = consolidatedPatterns["quarantineRemoval"].Strings()

	domains = domainsFromUrls(*consolidatedPatterns["urls"])
	stringFeat.UniqueDomains = domains.Strings()
	modelString.NumUniqueDomains = int32(domains.Len())

	if consolidatedPatterns["chromeExtensions"].Len() > 0 {
		for _, extId := range consolidatedPatterns["chromeExtensions"].Strings() {
			validation := &opb.ChromeExtensionValidation{
				ExtensionId:         extId,
				IsValid:             len(extId) == 32,
				ValidationAttempted: false,
				RawMatches:          []string{extId},
			}

			// Validate the extension
			validateChromeExtension(validation)
			if validation.IsValid && validation.IsActive {
				stringFeat.ChromeExtensions = append(stringFeat.ChromeExtensions, validation)
			}
		}
	}
	atSymbolsAgg := consolidatedPatterns["atSymbols"].Strings()
	sort.Strings(atSymbolsAgg)
	stringFeat.UniqueSymbolsWithAt = atSymbolsAgg

	modelString.NumStrings = stringsLen
	modelString.AvgLength = handleNanFloat((float64(lenSum)) / (float64(stringsLen)))
	for _, l := range lengths {
		if float64(l) > modelString.AvgLength {
			modelString.NumLongerThanAvg++
		}
	}

	modelString.EntStats = stringStatistics(r, processedStrings)
	if retAllStrings {
		stringFeat.AllStrings = strings.Join(rawStrings, "\n")
	}

	return stringFeat, modelString
}

// updateFeatures analyzes a string and updates persistence-related feature counters.
// Searches for patterns indicating LaunchAgents, LaunchDaemons, and StartupItems.
func updateFeatures(modelString *opb.StringModel, matchString string, consolidatedPatterns map[string]*StringSet) {
	// Persistence related features.
	if reLaunchAgent.MatchString(matchString) {
		modelString.Persistence.NumLaunchAgentPath++
	}
	if reLaunchDaemon.MatchString(matchString) {
		modelString.Persistence.NumLaunchDaemonPath++
	}
	if reStartupItems.MatchString(matchString) {
		modelString.Persistence.NumStartupItems++
	}
	if reScriptingAddition.MatchString(matchString) {
		modelString.Persistence.NumScriptingAddition++
	}
	if reLoginWindows.MatchString(matchString) {
		modelString.Persistence.NumLoginWindow++
	}
	if reLoginItems.MatchString(matchString) {
		modelString.Persistence.NumLoginItems++
	}
	if reShellStartupFiles.MatchString(matchString) {
		modelString.Persistence.NumShellStartupFiles++
	}
	if reCrontab.MatchString(matchString) {
		modelString.Persistence.NumCrontab++
	}

	// Privilege escalation features.
	if reSQLite.MatchString(matchString) {
		modelString.PrivEsc.NumSqlLite++
	}
	if reTCCDb.MatchString(matchString) {
		modelString.PrivEsc.NumTcc++
	}

	// Information Stealer and Security Bypass Detection Features.
	// Use a configuration structure to reduce code duplication
	type patternMatcher struct {
		re      *regexp.Regexp
		counter *int32
		key     string
	}

	securityPatterns := []patternMatcher{
		// Information Stealer Detection Features - Reduced to most reliable patterns only
		{re: reKeychainAccess, counter: &modelString.NumKeychainAccess, key: "keychainAccess"},
		{re: reDiscordWebhooks, counter: &modelString.NumDiscordWebhooks, key: "discordWebhooks"},
		// macOS Security Bypass Detection Features
		{re: reGatekeeperBypass, counter: &modelString.NumGatekeeperBypass, key: "gatekeeperBypass"},
		{re: reQuarantineRemoval, counter: &modelString.NumQuarantineRemoval, key: "quarantineRemoval"},
	}

	for _, pattern := range securityPatterns {
		if pattern.re.MatchString(matchString) {
			*pattern.counter++
			consolidatedPatterns[pattern.key].Add(matchString)
		}
	}
}

// stringStatistics returns different entropy metrics given a slice of strings.
func stringStatistics(r *MachoReader, strs []string) *opb.EntStat {
	var ents []float64
	for _, str := range strs {
		ents = append(ents, StringEntropy(str))
	}
	statMode, _ := stat.Mode(ents, nil)
	maxEnt := 0.0
	for _, ent := range ents {
		if ent > maxEnt {
			maxEnt = ent
		}
	}

	return &opb.EntStat{
		MeanEntropy: handleNanFloat(stat.Mean(ents, nil)),
		ModeEntropy: handleNanFloat(statMode),
		MaxEntropy:  handleNanFloat(maxEnt),
	}
}

// fetchSymbols returns symbols related information from the binary.
// allSymValues is a flag that indicates whether we want to return all the string
// symbols values.
func fetchSymbols(r *MachoReader, allSymValues bool) *opb.Symbol {
	symResult := &opb.Symbol{
		ExtSyms:    []string{},
		ExtSymHash: "",
		AllSyms:    []string{},
		AllSymHash: "",
	}
	machoFile := r.MachoReader
	if machoFile == nil || machoFile.Magic == types.MagicFat {
		return symResult
	}

	// If symbol table command is nil, we don't expect any references.
	// If dynamic symbol table command is nil, we don't expect external
	// references.
	if machoFile.Symtab == nil || machoFile.Dysymtab == nil {
		return symResult
	}

	var (
		hash                string
		err                 error
		extSyms, allSymbols StringSet
	)

	extSyms.NewStringSet()
	allSymbols.NewStringSet()

	symbols := machoFile.Symtab.Syms
	// We only hash external symbols to reduce self-referencing noise.
	for _, symbol := range symbols {
		if symbol.Type&0x0E == 0 && symbol.Name != "" {
			extSyms.Add(symbol.Name)
		}
		if allSymValues && symbol.Name != "" {
			allSymbols.Add(symbol.Name)
		}
	}

	if extSyms.Len() > 0 {
		symResult.ExtSyms = extSyms.Strings()

		hash, err = hashObject([]byte(strings.Join(symResult.ExtSyms, ",")), SHA256)
		if err != nil {
			ErrorLogger.Printf("could not hash external symbols : %v", err)
		}
		symResult.ExtSymHash = hash
	}

	allSyms := allSymbols.Strings()
	// User wants to see all the symbols in the binary.
	if allSymValues && len(allSyms) > 0 {
		symResult.AllSyms = allSymbols.Strings()
	}
	if len(allSyms) > 0 {
		hash, err = hashObject([]byte(strings.Join(symResult.AllSyms, ",")), SHA256)
		if err != nil {
			ErrorLogger.Printf("could not hash all symbols : %v", err)
		}
		symResult.AllSymHash = hash
	}

	return symResult
}

func getCodeSigning(r *MachoReader) (*opb.CertFeaturesML, []*opb.Certificate) {
	cFeat := &opb.CertFeaturesML{
		IsSigned:             false,
		IsSelfSigned:         false,
		IsSignedByCa:         false,
		IsCertificateRevoked: false,
		IsAdHoc:              false,
	}
	var certs []*opb.Certificate

	codeSignature := getCodeSignature(r)
	if codeSignature == nil {
		return cFeat, certs
	}

	// Check for ADHOC signing by examining code directories
	if codeSignature != nil && len(codeSignature.CodeDirectories) > 0 {
		for _, cd := range codeSignature.CodeDirectories {
			if reflect.TypeOf(cd) != nil && reflect.TypeOf(cd.Header.CdEarliest) != nil {
				// ADHOC flag value is 0x00000002
				const ADHOC = 0x00000002
				if (cd.Header.CdEarliest.Flags & ADHOC) != 0 {
					cFeat.IsAdHoc = true
					break // Found ADHOC signing, no need to check other code directories
				}
			}
		}
	}

	certificates := extractCertificates(codeSignature)
	if len(certificates) == 0 {
		return cFeat, certs
	}

	cFeat, certs = getCerts(certificates, cFeat, certs)

	// Check certificate revocation
	checkRevocation(certificates, cFeat, certs)

	return cFeat, certs
}

func extractCertificates(codeSignature *macho.CodeSignature) []*x509.Certificate {
	var certificates []*x509.Certificate

	// Extract entitlements certificates
	entitlementCerts, err := x509.ParseCertificates(codeSignature.EntitlementsDER)
	if err != nil {
		ErrorLogger.Print(err)
	}
	certificates = append(certificates, entitlementCerts...)

	// Extract CMS signature certificates using go.mozilla.org/pkcs7 package
	p7, err := pkcs7.Parse(codeSignature.CMSSignature)
	if err != nil {
		ErrorLogger.Printf("error: could not parse the CMS Signature %v", err)
	} else if p7 != nil && len(p7.Certificates) > 0 {
		certificates = append(certificates, p7.Certificates...)
	}

	return certificates
}

func checkRevocation(certificates []*x509.Certificate, cFeat *opb.CertFeaturesML, certs []*opb.Certificate) {
	if len(certificates) == 0 || len(certs) == 0 {
		return
	}

	ocspResponse, err := isCertRevoked(certificates)
	if err != nil {
		ErrorLogger.Println(fmt.Errorf("error: could not check if cert is revoked: %v", err))
		return
	}

	if !ocspResponse.RevokedAt.IsZero() {
		cFeat.IsCertificateRevoked = true

		timestampval := timestamppb.New(ocspResponse.RevokedAt)

		// Use proper leaf identification instead of position-based logic
		leafIndex := -1
		for i, cert := range certs {
			if cert.IsLeaf {
				leafIndex = i
				break
			}
		}

		// If we found a leaf certificate, assign the revocation time
		if leafIndex >= 0 && leafIndex < len(certs) {
			certs[leafIndex].RevokedAt = timestampval
		} else {
			WarningLogger.Printf("Could not find leaf certificate to assign revocation time")
		}
	}
}

// identifyLeafAndIssuer reliably identifies the leaf certificate and its direct issuer
// by analyzing the certificate chain structure and validation relationships
func identifyLeafAndIssuer(certs []*x509.Certificate) (*x509.Certificate, *x509.Certificate, error) {
	if len(certs) < 2 {
		return nil, nil, fmt.Errorf("need at least 2 certificates")
	}

	// Find the leaf certificate (end-entity cert that isn't a CA and can't verify others)
	var leafCert *x509.Certificate
	for _, cert := range certs {
		if cert.IsCA {
			continue // Skip CA certificates
		}

		// Check if this cert can verify any other cert in the chain
		canVerifyOthers := false
		for _, otherCert := range certs {
			if cert == otherCert {
				continue
			}
			if otherCert.CheckSignatureFrom(cert) == nil {
				canVerifyOthers = true
				break
			}
		}

		if !canVerifyOthers {
			leafCert = cert
			break
		}
	}

	if leafCert == nil {
		return nil, nil, fmt.Errorf("could not identify leaf certificate")
	}

	// Find the direct issuer of the leaf certificate
	for _, cert := range certs {
		if cert == leafCert {
			continue
		}
		if leafCert.CheckSignatureFrom(cert) == nil {
			return leafCert, cert, nil
		}
	}

	return nil, nil, fmt.Errorf("could not identify issuer certificate")
}

func isCertRevoked(certs []*x509.Certificate) (*ocsp.Response, error) {
	if len(certs) < 2 {
		return nil, errCertNotFound
	}

	// Try to identify certificates using chain analysis
	leafCert, issuerCert, err := identifyLeafAndIssuer(certs)
	if err != nil {
		// Fallback to original indexing with validation
		potentialLeaf := certs[len(certs)-1]
		potentialIssuer := certs[0]

		// Validate the signature relationship
		if potentialLeaf.CheckSignatureFrom(potentialIssuer) == nil {
			leafCert = potentialLeaf
			issuerCert = potentialIssuer
		} else {
			return nil, fmt.Errorf("certificate chain analysis failed: %v", err)
		}
	}

	// Determine OCSP URL - prefer leaf cert's OCSP server if available
	var ocspURL string
	if len(leafCert.OCSPServer) > 0 {
		ocspURL = leafCert.OCSPServer[0]
	} else if len(issuerCert.OCSPServer) > 0 {
		ocspURL = issuerCert.OCSPServer[0]
	} else {
		// Fallback: search for any cert with OCSP URL, but still use certs[1] as issuer
		for _, cert := range certs[1:] {
			if len(cert.OCSPServer) > 0 {
				ocspURL = cert.OCSPServer[0]
				break
			}
		}
	}

	if ocspURL == "" {
		return nil, errNoOCSPServer
	}

	// Verify issuer relationship
	if err := leafCert.CheckSignatureFrom(issuerCert); err != nil {
		return nil, fmt.Errorf("issuer certificate verification failed: %v", err)
	}

	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
	buffer, err := ocsp.CreateRequest(leafCert, issuerCert, opts)
	if err != nil {
		return nil, errCreateReq
	}

	// Rest of your HTTP request logic...
	httpRequest, err := http.NewRequest(http.MethodPost, ocspURL, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, errCreateHTTPReq
	}

	parsedURL, err := url.Parse(ocspURL)
	if err != nil {
		return nil, errCreateReq
	}

	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("Host", parsedURL.Host)

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, errCreateHTTPReq
	}
	defer httpResponse.Body.Close()

	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, errInvalidResp
	}

	return ocsp.ParseResponseForCert(output, leafCert, issuerCert)
}

// netIPToString converts a slice of net.IP addresses to string representations.
// Used for certificate analysis and network-related feature extraction.
func netIPToString(ips []net.IP) []string {
	var ipAddrs []string
	for _, ip := range ips {
		ipAddrs = append(ipAddrs, ip.String())
	}
	return ipAddrs
}

// isCertificateSelfSigned determines if a certificate is self-signed using cryptographic validation
func isCertificateSelfSigned(cert *x509.Certificate) bool {
	// A certificate is self-signed if:
	// 1. The issuer and subject are identical
	// 2. AND the certificate can verify its own signature (or fails due to insecure algorithm)
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}

	// Verify that the certificate can sign itself
	err := cert.CheckSignatureFrom(cert)
	isSelfSigned := err == nil

	// Special case: If signature verification fails due to insecure algorithm (like SHA1-RSA),
	// we still consider it self-signed if it's a CA certificate with matching subject/issuer
	if err != nil && cert.IsCA && strings.Contains(err.Error(), "insecure algorithm") {
		isSelfSigned = true
	}

	return isSelfSigned
}

// isCertificateValid determines if a certificate is cryptographically valid
func isCertificateValid(cert *x509.Certificate) bool {
	// For self-signed certificates, check if they can verify their own signature
	if cert.Subject.String() == cert.Issuer.String() {
		err := cert.CheckSignatureFrom(cert)
		if err != nil {
			errMsg := err.Error()

			// Only ignore time and algorithm deprecation issues
			safeToIgnore := []string{
				"insecure algorithm", // MD5, SHA-1 deprecation
				"certificate expired",
				"certificate not yet valid",
			}

			for _, pattern := range safeToIgnore {
				if strings.Contains(errMsg, pattern) {
					return true
				}
			}

			return false // Fail on structural/key validity issues
		}
		return true
	}

	// For CA-signed certificates, we would need the issuer certificate to validate
	// For now, assume valid if not self-signed (this is a simplified approach)
	// In a full implementation, we would validate the signature against the issuer
	return true
}

// setCertificateRole determines and sets the certificate role fields based on cryptographic properties
func setCertificateRole(cert *opb.Certificate, chainPosition int, isCA bool, isSelfSigned bool) {
	// Reset all role flags
	cert.IsLeaf = false
	cert.IsIntermediate = false
	cert.IsRoot = false
	cert.ChainPosition = int32(chainPosition)

	// Assign role based on cryptographic properties, not position
	if isSelfSigned && isCA {
		// Self-signed CA certificate is a root
		cert.IsRoot = true
	} else if isCA {
		// CA certificate that's not self-signed is intermediate
		cert.IsIntermediate = true
	} else {
		// Non-CA certificate is the leaf (end-entity)
		cert.IsLeaf = true
	}
}

func getCerts(etcerts []*x509.Certificate, cFeat *opb.CertFeaturesML, certs []*opb.Certificate) (*opb.CertFeaturesML, []*opb.Certificate) {
	if len(etcerts) == 0 {
		return cFeat, certs
	}

	hasCASigned := false
	hasSelfSigned := false
	hasValidCertificates := true
	maxNumCerts := 0

	for idx, cert := range etcerts {
		maxNumCerts += 1
		c := &opb.Certificate{
			Sans:        cert.DNSNames,
			Emails:      cert.EmailAddresses,
			IpAddresses: netIPToString(cert.IPAddresses),
			// We used the text representation of the serial number because the output
			// will conform to the serial number hex output seen in platforms like VT.
			SerialNumber: cert.SerialNumber.Text(16),
			Issuer: &opb.CertIssuerSubj{
				IssuerName:     cert.Issuer.CommonName,
				IssuerCountry:  strings.Join(cert.Issuer.Country, ","),
				IssuerOrg:      strings.Join(cert.Issuer.Organization, ","),
				SubjectName:    cert.Subject.CommonName,
				SubjectOrg:     strings.Join(cert.Subject.Organization, ","),
				SubjectOrgUnit: strings.Join(cert.Subject.OrganizationalUnit, ","),
			},
			IsCaSigned: cert.IsCA,
			IsCa:       cert.IsCA,
			ValidFrom:  cert.NotBefore.String(),
			ValidTo:    cert.NotAfter.String(),
		}

		// Determine certificate role using cryptographic properties
		isSelfSigned := isCertificateSelfSigned(cert)
		setCertificateRole(c, idx, cert.IsCA, isSelfSigned)

		// Check certificate validity for both individual and chain-level tracking
		isValidCert := isCertificateValid(cert)
		c.IsValidCert = isValidCert
		if !isValidCert {
			hasValidCertificates = false
		}

		if cert.IsCA {
			cFeat.IsSignedByCa = true
			hasCASigned = true
		}

		certs = append(certs, c)
	}

	// Determine if the entire chain is self-signed
	// A chain is "self-signed" if ALL certificates in the chain have self-signed attempts
	// (subject/issuer match) - this is the informational aspect
	// For cryptographic validation, we use isCertificateSelfSigned() which checks signature
	if len(etcerts) == 1 {
		// Single certificate chain - self-signed if subject/issuer match (informational)
		hasSelfSigned = etcerts[0].Subject.String() == etcerts[0].Issuer.String()

	} else {
		// Multiple certificate chain - only self-signed if ALL certificates have self-signed attempts
		allSelfSignedAttempt := true
		for _, cert := range etcerts {
			if cert.Subject.String() != cert.Issuer.String() {
				allSelfSignedAttempt = false
				break
			}
		}
		hasSelfSigned = allSelfSignedAttempt
	}

	// Set certificate features directly here
	if len(certs) > 0 {
		cFeat.IsSigned = true
	}
	cFeat.IsSelfSigned = hasSelfSigned
	cFeat.IsValidCert = hasValidCertificates

	// Set IsCaSigned flag on all certificates that are signed by a CA
	// and also on the leaf certificate if there's a CA in the chain
	if hasCASigned {
		// All certificates in a CA-signed chain should have IsCaSigned = true
		for i := range certs {
			certs[i].IsCaSigned = true
		}
	}

	return cFeat, certs
}

// teamUUID extracts the team identifier UUID from a Mach-O binary.
// Returns empty string if no UUID is present in the binary.
func teamUUID(r *MachoReader) string {
	uuid := r.MachoReader.UUID()
	if uuid == nil {
		return ""
	}
	return uuid.UUID.String()
}

func getDyLibFeatures(r *MachoReader) *opb.DylibFeatures {
	dylibFeat := &opb.DylibFeatures{
		Dylibs:            []*opb.Dylib{},
		NumDylibs:         0,
		HasAudiovisualCap: false,
		HasSecurityCap:    false,
		HasLocationCap:    false,
		HasPersonalDat:    false,
		HasDiskCap:        false,
	}

	if dylibs := r.MachoReader.ImportedLibraries(); dylibs != nil {
		dylibFeat.Dylibs = make([]*opb.Dylib, 0, len(dylibs))
		for _, lib := range dylibs {
			dlb := &opb.Dylib{
				Name:              lib,
				CurrentVersion:    "",
				CompatibleVersion: "",
				Time:              0,
			}
			dylibFeat.Dylibs = append(dylibFeat.Dylibs, dlb)

			for cap, capCategory := range frameworkCap {
				if !strings.Contains(dlb.Name, cap) {
					continue
				}
				switch capCategory {
				case PersonalData:
					dylibFeat.HasPersonalDat = true
				case Security:
					dylibFeat.HasSecurityCap = true
				case AudioVideo:
					dylibFeat.HasAudiovisualCap = true
				case Location:
					dylibFeat.HasLocationCap = true
				case PhysicalVolumes:
					dylibFeat.HasDiskCap = true
				}
			}
		}
		dylibFeat.NumDylibs = int32(len(dylibFeat.Dylibs))
	}
	return dylibFeat
}

func getSectionFeatures(r *MachoReader) *opb.Section {
	sRes := &opb.Section{
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
	sections := r.MachoReader.FileTOC.Sections
	if sections == nil {
		return sRes
	}

	var flag StringSet
	var sEnts, sectEnts []float64

	flag.NewStringSet()
	relocTypes := make(map[uint8]bool)

	for _, section := range sections {
		sRes.SumSecSize += int32(section.Size)
		sRes.NumOfReloc += int32(section.Nreloc)

		sRes.NumSecFlags += int32(len(section.Flags.List()))
		flag.Add(section.Flags.List()...)

		sRes.NumAttributes += int32(len(section.Flags.AttributesList()))
		flags := section.Flags
		// Assert that the attribute is already false.
		// We don't want to update any of they HasAttribute features
		// if we already encountered a true state.
		if !sRes.HasDebugAttribute {
			sRes.HasDebugAttribute = flags.IsDebug()
		}
		if !sRes.HasSelfModifyingCode {
			sRes.HasSelfModifyingCode = flags.IsSelfModifyingCode()
		}
		if !sRes.HasCStringLiterals {
			sRes.HasCStringLiterals = flags.IsCstringLiterals()
		}
		if !sRes.HasStripSymbols {
			sRes.HasStripSymbols = flags.IsStripStaticSyms()
		}
		if strings.Contains(section.Name, "__text") {
			sectDat, err := section.Data()
			if err != nil {
				ErrorLogger.Printf("error: could not get the data from the text section: %v", err)
			}
			sectEnts = append(sectEnts, byteEntropy(sectDat))
			sRes.NumTextSec++
		}
		if strings.Contains(section.Name, "__data") {
			sRes.NumDataSections++
		}
		if section.Size == 0 {
			sRes.NumSecZeroSize++
		}
		if section.Size > 0 {
			sRes.NumSecNonZeroSize++
		}

		// Calculate entropy for this section name and store it individually
		sectionNameEntropy := StringEntropy(section.Name)
		sEnts = append(sEnts, sectionNameEntropy)
		sRes.SectionEntropies[section.Name] = sectionNameEntropy

		relocations := section.Relocs
		if len(relocations) > 0 {
			for _, reloc := range relocations {
				relocTypes[reloc.Type] = true
			}
		}
	}

	sRes.NumSections = int32(len(sections))
	sRes.UniqueNumSecFlags = int32(flag.Len())
	sRes.UniqueNumRelocTypes = int32(len(relocTypes))

	// Compute the mean entropy of the data in the "__text" sections.
	sRes.MeanTextSecEntropy = handleNanFloat(stat.Mean(sectEnts, nil))

	// Compute the entropy stats for the different section names.
	sRes.MeanSecNameEntropy = handleNanFloat(stat.Mean(sEnts, nil))
	m, _ := stat.Mode(sEnts, nil)
	sRes.ModeSecNameEntropy = handleNanFloat(m)
	sRes.MomentSecNameEntropy = handleNanFloat(stat.Moment(1, sEnts, nil))

	return sRes
}

func getSegmentFeatures(r *MachoReader) *opb.Segment {
	segRes := &opb.Segment{
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
	segments := r.MachoReader.Segments()
	if segments == nil {
		return segRes
	}

	var flags StringSet
	flags.NewStringSet()
	for _, segment := range segments {
		// populate the VM protect fields
		VMProtect := fmt.Sprintf("%s|%s", segment.Maxprot.String(), segment.Prot.String())
		switch segment.Name {
		case pageZeroName:
			segRes.HasEmptyPageZeroSeg = true

			// Check if segment has file data before reading
			if segment.Filesz == 0 {
				// Empty segment, assume it's empty (all zeros)
				break
			}

			if segment.Filesz == 0 {
				ErrorLogger.Printf("segment %s has no file size, skipping zero-check", segment.Name)
				break
			}

			d, err := segment.Data()
			if err != nil {
				ErrorLogger.Printf("unable to fetch the data contents of %s segment. err:%v", segment.Name, err)
				break // Skip the zero-check if we can't read data
			}

			for _, v := range d {
				if v != 0 {
					segRes.HasEmptyPageZeroSeg = false
					break
				}
			}

		case textName:
			segRes.TxtSegVmProt = VMProtect
		case dataName:
			segRes.DataSegVmProt = VMProtect
		case linkEditName:
			segRes.LnkEditSegVmProt = VMProtect
		}

		segRes.SumSegMemSize += int32(segment.Memsz)
		segRes.SumSegFileSize += int32(segment.Filesz)

		segRes.NumSegments++

		flags.Add(segment.Flag.List()...)
	}
	segRes.UniqueSegFlags = flags.Strings()
	return segRes
}

func getDySymTabFeatures(r *MachoReader) *opb.DySymTabFeatures {
	dysmFeat := &opb.DySymTabFeatures{
		NumExternalDefines:   0,
		NumExternalReference: 0,
		NumExternalReloc:     0,
	}
	dst := r.MachoReader.Dysymtab
	if dst == nil {
		return dysmFeat
	}

	dysmFeat.NumExternalDefines = int32(dst.Nextdefsym)
	dysmFeat.NumExternalReference = int32(dst.Nextrefsyms)
	dysmFeat.NumExternalReloc = int32(dst.Nextrel)
	return dysmFeat
}

func getDyldFeatures(r *MachoReader) *opb.DyldInfo {
	dylibFeat := &opb.DyldInfo{
		RebaseSize:   0,
		BindSize:     0,
		LazyBindSize: 0,
		ExportSize:   0,
	}

	if d := r.MachoReader.DyldInfo(); d != nil {
		dylibFeat.BindSize = int32(d.BindSize)
		dylibFeat.ExportSize = int32(d.ExportSize)
		dylibFeat.LazyBindSize = int32(d.LazyBindSize)
		dylibFeat.RebaseSize = int32(d.RebaseSize)
		return dylibFeat
	}

	if d := r.MachoReader.DyldInfoOnly(); d != nil {
		dylibFeat.BindSize = int32(d.BindSize)
		dylibFeat.ExportSize = int32(d.ExportSize)
		dylibFeat.LazyBindSize = int32(d.LazyBindSize)
		dylibFeat.RebaseSize = int32(d.RebaseSize)

		return dylibFeat
	}

	ErrorLogger.Println(errFetchingDYLD)
	return dylibFeat
}

func validateChromeExtension(validation *opb.ChromeExtensionValidation) {
	validation.IsValid = len(validation.ExtensionId) == 32 && reChromeExtensionId.MatchString(validation.ExtensionId)

	if validation.IsValid {
		validation.ValidationAttempted = true

		if info, err := fetchExtensionInfo(validation.ExtensionId); err == nil {
			validation.IsActive = true
			validation.Name = info.Name
			validation.Version = info.Version
			validation.Description = info.Description
		} else {
			validation.ErrorMsg = err.Error()
		}
	} else {
		validation.ErrorMsg = "Invalid extension ID format"
	}
}

func fetchExtensionInfo(extensionId string) (*ChromeExtensionInfo, error) {
	q := url.Values{}
	chromeProdVersion := "123.0.0.0"

	q.Set("response", "updatecheck")
	q.Set("prodversion", chromeProdVersion)
	q.Set("x", fmt.Sprintf("id=%s&uc", extensionId))
	u := chromeExtensionValidationURL + "?" + q.Encode()

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	userAgent := "curl/8"
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call update service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update service returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read update service response: %v", err)
	}

	var gu gupdate
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	dec.Strict = false
	if err := dec.Decode(&gu); err != nil {
		return nil, fmt.Errorf("failed to parse update XML: %v", err)
	}

	appStatus := strings.ToLower(strings.TrimSpace(gu.App.Status))
	updStatus := strings.ToLower(strings.TrimSpace(gu.App.UpdateCheck.Status))
	version := strings.TrimSpace(gu.App.UpdateCheck.Version)

	if strings.HasPrefix(appStatus, "error-") {
		return nil, fmt.Errorf("extension not found or inactive (app status: %s)", appStatus)
	}

	if appStatus == "ok" {
		if updStatus == "ok" || updStatus == "noupdate" || updStatus == "" {
			return &ChromeExtensionInfo{
				Name:        "",
				Version:     version,
				Description: "",
			}, nil
		}
		return nil, fmt.Errorf("extension active but updatecheck returned %q", updStatus)
	}

	return nil, fmt.Errorf("extension not found or inactive (app status: %s)", appStatus)
}

// isValidPath validates if a path string represents a real file system path
func isValidPath(path string) bool {
	// Remove leading/trailing whitespace
	path = strings.TrimSpace(path)

	// Must be non-empty and start with / for absolute Unix paths
	if len(path) < 2 || !strings.HasPrefix(path, "/") {
		return false
	}

	// Cannot be just the root "/"
	if path == "/" {
		return false
	}

	// Split into components and validate structure
	parts := strings.Split(path, "/")
	validComponents := 0

	for i, part := range parts {
		// Skip the empty part from leading slash
		if i == 0 && part == "" {
			continue
		}

		// Empty components in middle indicate double slashes (//) - invalid
		if part == "" {
			return false
		}

		// Check if component looks like a filesystem name
		if !isValidFilesystemComponent(part) {
			return false
		}

		validComponents++
	}

	// Must have at least one valid component after the leading slash
	return validComponents >= 1
}

// isValidFilesystemComponent determines if a string looks like a valid filesystem component
func isValidFilesystemComponent(component string) bool {
	if len(component) == 0 || len(component) > 255 {
		return false
	}

	// Check for null bytes (forbidden in Unix)
	if strings.ContainsRune(component, 0) {
		return false
	}

	// Check for obvious programming artifacts
	if hasProgrammingArtifacts(component) {
		return false
	}

	return true
}

// hasProgrammingArtifacts detects common programming patterns that aren't filesystem paths
func hasProgrammingArtifacts(s string) bool {
	// Invalid filesystem characters: forbidden in Unix/Windows filesystems
	forbiddenChars := ":/=&|;`$*?\\\"'"
	if strings.ContainsAny(s, forbiddenChars) {
		return true
	}

	// Format string detection: common format specifiers
	if strings.Contains(s, "%s") || strings.Contains(s, "%d") || strings.Contains(s, "%%") {
		return true
	}

	// Programming syntax: parentheses, brackets, arrows
	if strings.ContainsAny(s, "()[]{}<>") ||
		strings.Contains(s, "->") ||
		strings.Contains(s, "::") ||
		strings.Contains(s, ".(") ||
		strings.Contains(s, ").") {
		return true
	}

	// Package notation detection: multiple dots with consistent word patterns
	if hasPackageNotation(s) {
		return true
	}

	return false
}

// hasPackageNotation detects programming package notation using simple logic
func hasPackageNotation(s string) bool {
	// Simple rule: 3 or more dots suggest package notation
	// Most filenames have 0-2 dots (name.ext, file.backup.old)
	// Package notation typically has 3+ (org.apache.commons.lang)
	return strings.Count(s, ".") >= 3
}
