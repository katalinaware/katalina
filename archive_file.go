package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	outputDir     = "Temp"
	arch          = runtime.GOARCH
	systemOS      = runtime.GOOS
	osSeparator   = string(filepath.Separator)
	plistRegex    = regexp.MustCompile(`Path = (.*)Info.plist(.*)\n`)
	contPathRegex = regexp.MustCompile(`Path = (.*)Contents[\\/]MacOS[\\/](.*?)s*\n`)
)

// MachoCandidates returns a set of valid macho candidates.
func MachoCandidates(contentPaths []string) []string {
	var machoFiles []string
	for _, path := range contentPaths {
		path := filepath.Join(outputDir, path)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}

		contentPath := filepath.Join("Contents", "MacOS")
		// The path is just the MacOS directory and not a file in it.
		if strings.HasSuffix(path, contentPath) {
			continue
		}
		machoFiles = append(machoFiles, strings.TrimSpace(path))
	}
	return machoFiles
}

// HasPlistPath determines if the list of strings matches the the Info.plist pattern.
func HasPlistPath(paths []string) bool {
	hasPlist := false
	for _, p := range paths {
		if len(plistRegex.FindString(p)) > 0 {
			hasPlist = true
		}
		if hasPlist {
			break
		}
	}
	return hasPlist
}

// PlistPath returns all the plist paths that match the Info.plist pattern.
func PlistPaths(paths []string) []string {
	var plistPaths []string
	for _, p := range paths {
		plistPath := Clean7zPath(plistRegex.FindString(p))
		if len(plistPath) > 0 {
			plistPath = filepath.Join(outputDir, plistPath)
			plistPaths = append(plistPaths, plistPath)
		}
	}
	return plistPaths
}

// ContentDirectory determines if the archive has a content\macos directory.
func ContentDirectory(paths []string) []string {
	var contentPaths []string
	for _, p := range paths {
		contentPath := contPathRegex.FindString(p)
		if len(contentPath) > 0 {
			contentPath = Clean7zPath(contentPath)
			contentPaths = append(contentPaths, contentPath)
		}
	}
	return contentPaths
}

// Given a path from a 7z list operation, return the path without the surrounding context.
func Clean7zPath(path string) string {
	contentPath := strings.TrimSpace(strings.ReplaceAll(path, "Path = ", ""))
	return contentPath
}

// CreateTempDir creates a temporary directory under the OS temp directory.
func CreateTempDir(dirName string) (string, error) {
	tempDir := os.TempDir()
	newDirPath := filepath.Join(tempDir, dirName)

	if _, err := os.Stat(newDirPath); os.IsNotExist(err) {
		err := os.Mkdir(newDirPath, 0755)
		if err != nil {
			return "", fmt.Errorf("error creating directory under tempDir: %v", err)
		}
	} else if err != nil {
		return "", fmt.Errorf("error checking if directory under tempDir exits: %v", err)
	}

	return newDirPath, nil
}

// sevenZPath returns the path to the 7z binary as found int the repo.
func sevenZPath(OS, arch string) (string, error) {
	var (
		repoPath7z, tempFilePath string
		err                      error
	)

	switch OS + "-" + arch {
	case "windows-amd64":
		repoPath7z = path.Join("binaries", "windows", "amd64", "7z.exe")
	case "linux-amd64":
		repoPath7z = path.Join("binaries", "linux", "amd64", "7zz")
	case "linux-arm64":
		repoPath7z = path.Join("binaries", "linux", "arm64", "7zz")
	case "darwin-amd64", "darwin-arm64":
		repoPath7z = path.Join("binaries", "darwin", "7zz")
	default:
		return "", fmt.Errorf("error: could not find 7z binary for %s-%s", OS, arch)
	}

	embedded7zFile, err := binaries.Open(repoPath7z)
	if err != nil {
		return "", fmt.Errorf("error: could not read golang embeded 7z binary: %v", err)
	}

	tempDirPath, err := CreateTempDir("sevenZ")
	if err != nil {
		return "", err
	}

	if OS == "windows" {
		tempFilePath = filepath.Join(tempDirPath, fmt.Sprintf("%s_%s_7z.exe", OS, arch))
	} else {
		tempFilePath = filepath.Join(tempDirPath, fmt.Sprintf("%s_%s_7zz", OS, arch))
	}

	tempFile, err := os.OpenFile(tempFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("error: could not create temporary file: %v", err)
	}
	defer tempFile.Close()

	// Copy the content from the embedded file to the new file.
	_, err = io.Copy(tempFile, embedded7zFile)
	if err != nil {
		return "", fmt.Errorf("error: could not copy content from embedded 7z file to the new temp 7z file: %v", err)
	}

	return tempFilePath, nil
}

// AllPaths returns the list of all paths from a compressed object.
func AllPaths(path string) ([]string, error) {
	seven7zPath, err := sevenZPath(systemOS, arch)
	if err != nil {
		os.Remove(seven7zPath)
		return nil, err
	}
	defer os.Remove(seven7zPath)

	stdout, err := exec.Command(seven7zPath, "l", path, "-slt").Output()
	if err != nil {
		return nil, err
	}
	lo := string(stdout)
	allPaths := regexp.MustCompile(`Path = (.*)\n`)
	paths := allPaths.FindAllString(lo, -1)
	return paths, nil
}

// ExtractArchive extracts the archive to a temporary directory.
func ExtractArchive(path string) error {
	seven7zPath, err := sevenZPath(systemOS, arch)
	if err != nil {
		return err
	}

	_, err = exec.Command(seven7zPath, "x", path, fmt.Sprintf("-o%s%s", outputDir, osSeparator), "-y").Output()
	if err != nil && cmp.Equal(err, errors.New("exit status 2"), cmpopts.EquateErrors()) {
		return fmt.Errorf("error: could not extract archive: %v", err)
	}

	if _, err := os.Stat(outputDir); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("error: could not extract archive, directory was not created")
	}
	return nil
}

// CleanUpTemp delete directory that were temporarily created.
func CleanUpTemp(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("error: directory does not exist")
	}

	return os.RemoveAll(path)
}
