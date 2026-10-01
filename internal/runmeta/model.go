package runmeta

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Source is an observed process/module identity, not an authenticity proof.
// StartTicks and BootID prevent PID reuse from silently binding different processes.
type Source struct {
	PID           uint32 `json:"pid,omitempty"`
	UID           string `json:"uid,omitempty"`
	ProcessName   string `json:"process_name,omitempty"`
	StartTicks    string `json:"start_ticks,omitempty"`
	BootID        string `json:"boot_id,omitempty"`
	IdentityError string `json:"identity_error,omitempty"`
	ModulePath    string `json:"module_path,omitempty"`
	Base          string `json:"base,omitempty"`
	ExpectedBytes uint64 `json:"expected_bytes,omitempty"`
	ReadBytes     uint64 `json:"read_bytes,omitempty"`
}

type Artifact struct {
	Note      string   `json:"note,omitempty"`
	ID        string   `json:"id"`
	Path      string   `json:"path"`
	Kind      string   `json:"kind"`
	SHA256    string   `json:"sha256,omitempty"`
	Size      int64    `json:"size"`
	Status    string   `json:"status"`
	Source    Source   `json:"source"`
	Inputs    []string `json:"inputs,omitempty"`
	Operation string   `json:"operation,omitempty"`
	Error     string   `json:"error,omitempty"`
	Time      string   `json:"time"`
}

type RunManifest struct {
	SchemaVersion int        `json:"schema_version"`
	RunID         string     `json:"run_id"`
	Mode          string     `json:"mode"`
	Version       string     `json:"tool_version"`
	Started       string     `json:"started_at"`
	Ended         string     `json:"ended_at,omitempty"`
	Status        string     `json:"status"`
	Error         string     `json:"error,omitempty"`
	Artifacts     []Artifact `json:"artifacts"`
}

func SourceKey(s Source) string { return fmt.Sprintf("%d-%s-%s", s.PID, s.StartTicks, s.BootID) }
func SameModule(a, b Source) bool {
	return a.PID != 0 && a.StartTicks != "" && a.BootID != "" && a.ModulePath != "" && a.Base != "" && a.IdentityError == "" && b.IdentityError == "" && SourceKey(a) == SourceKey(b) && a.ModulePath == b.ModulePath && a.Base == b.Base
}

func DigestFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
