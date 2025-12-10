package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestContentDirectory(t *testing.T) {
	tests := []struct {
		desc  string
		paths []string
		want  []string
	}{
		{
			desc: "Has a valid content directory",
			paths: []string{
				filepath.Join("Path = mini", "Mini.App", "Contents", "MacOS\n"),
				filepath.Join("Path = mini", "Mini.App", "Contents", "MacOS", "Some App\n"),
				filepath.Join("Path = mini", "Mini.App", "SomethingElse", "MacOS\n"),
			},
			want: []string{filepath.Join("mini", "Mini.App", "Contents", "MacOS", "Some App")},
		},
		{
			desc: "Doesn't have a valid content directory",
			paths: []string{
				filepath.Join("Path = mini", "Mini.App", "SomethingElse", "MacOS\n"),
				filepath.Join("mini", "Mini.App", "Contents", "MacOS"),
				filepath.Join("mini", "Mini.App", "Contents", "MacOS\n"),
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := ContentDirectory(tt.paths)
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("ContentDirectory(%v) returned: %v expected %v", tt.paths, got, tt.want)
			}
		})
	}
}

func TestHasPlistPath(t *testing.T) {
	tests := []struct {
		desc  string
		paths []string
		want  bool
	}{
		{
			desc: "Has a valid Plist path",
			paths: []string{
				filepath.Join("Path = ", "Mini.App", "Contents", "Info.plist\n"),
				filepath.Join("Path = mini", "Mini.App", "SomethingElse", "MacOS\n"),
			},
			want: true,
		},
		{
			desc: "Doesn't a valid Plist path",
			paths: []string{
				filepath.Join("Path = ", "Mini.App", "Contents", "Something.plist\n"),
				filepath.Join("Path = mini", "Mini.App", "SomethingElse", "MacOS\n"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := HasPlistPath(tt.paths)
			if tt.want != got {
				t.Fatalf("HasPlistPath(%v) returned: %v expected %v", tt.paths, got, tt.want)
			}
		})
	}
}

func TestSevenZPath(t *testing.T) {
	tests := []struct {
		name    string
		OS      string
		arch    string
		want    string
		wantErr bool
	}{
		{"Windows amd64", "windows", "amd64", "7z.exe", false},
		{"Linux amd64", "linux", "amd64", "7zz", false},
		{"Linux arm64", "linux", "arm64", "7zz", false},
		{"Darwin amd64", "darwin", "amd64", "7zz", false},
		{"Darwin arm64", "darwin", "arm64", "7zz", false},
		{"Unsupported combination", "unknownOS", "unknownArch", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := sevenZPath(tt.OS, tt.arch)
			if tt.wantErr {
				if err == nil {
					t.Errorf("sevenZPath() for %s-%s; want error, got none", tt.OS, tt.arch)
				}
			} else {
				if err != nil {
					t.Errorf("sevenZPath() for %s-%s; unexpected error: %v", tt.OS, tt.arch, err)
				}
				if strings.HasSuffix(got, tt.want) == false {
					t.Errorf("sevenZPath() for %s-%s = %v, want %v", tt.OS, tt.arch, got, tt.want)
				}
			}
		})
	}
}

// TestRegexPath tests the regular expression for file paths on different OS.
func TestRegexPath(t *testing.T) {
	// Define test cases
	tests := []struct {
		name      string
		path      string
		wantMatch bool
	}{
		{"Unix-like valid path", "Path = /Applications/ExampleApp/Contents/MacOS/ExampleExecutable\n", true},
		{"Unix-like invalid path", "Invalid/Path = /Applications/WrongApp/Contents\n", false},
		{"Windows valid path", "Path = C:\\Program Files\\ExampleApp\\Contents\\MacOS\\ExampleExecutable\n", true},
		{"Windows invalid path", "Invalid\\Path = C:\\Program Files\\WrongApp\\Contents\n", false},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if match := contPathRegex.MatchString(tt.path); match != tt.wantMatch {
				t.Errorf("TestRegexPath() for %s; got %v, want %v", tt.name, match, tt.wantMatch)
			}
		})
	}
}
