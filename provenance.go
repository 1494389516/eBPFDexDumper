package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

type RunRecorder struct {
	sources  sync.Map // dexIdentity -> first observed Source
	mu       sync.Mutex
	Root     string
	manifest RunManifest
	events   *os.File
	err      error
	closed   bool
}

var activeRun atomic.Pointer[RunRecorder]

func newID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:]), nil
}

func NewRunRecorder(parent, mode string) (*RunRecorder, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(parent, id)
	if err = os.MkdirAll(parent, 0755); err != nil {
		return nil, err
	}
	if err = os.Mkdir(root, 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(root, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	version := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		version = bi.Main.Version
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				version = s.Value
			}
		}
	}
	r := &RunRecorder{Root: root, events: f, manifest: RunManifest{SchemaVersion: 1, RunID: id, Mode: mode, Version: version, Started: time.Now().UTC().Format(time.RFC3339Nano), Status: "running", Artifacts: []Artifact{}}}
	if err = r.persist(); err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

func (r *RunRecorder) persist() error {
	data, err := json.MarshalIndent(r.manifest, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(r.Root, ".manifest-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(r.Root, "manifest.json"))
}

func (r *RunRecorder) record(a Artifact) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("run recorder closed")
	}
	a.ID = fmt.Sprintf("%s:%d", r.manifest.RunID, len(r.manifest.Artifacts)+1)
	a.Time = time.Now().UTC().Format(time.RFC3339Nano)
	r.manifest.Artifacts = append(r.manifest.Artifacts, a)
	err := json.NewEncoder(r.events).Encode(a)
	if err == nil {
		err = r.events.Sync()
	}
	err = errors.Join(err, r.persist())
	r.err = errors.Join(r.err, err)
	return err
}

func (r *RunRecorder) Finish(cause error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.err
	}
	r.closed = true
	cause = errors.Join(cause, r.err)
	r.manifest.Ended = time.Now().UTC().Format(time.RFC3339Nano)
	r.manifest.Status = "completed"
	for _, a := range r.manifest.Artifacts {
		if a.Status == "failed" || a.Status == "partial" || a.Status == "degraded" {
			r.manifest.Status = "partial"
		}
	}
	if cause != nil {
		r.manifest.Status = "failed"
		r.manifest.Error = cause.Error()
	}
	r.err = errors.Join(cause, r.persist(), r.events.Close())
	return r.err
}

func startRecordedRun(parent, mode string) (*RunRecorder, error) {
	r, err := NewRunRecorder(parent, mode)
	if err != nil {
		return nil, err
	}
	if !activeRun.CompareAndSwap(nil, r) {
		r.Finish(errors.New("another run is active"))
		return nil, errors.New("another run is active")
	}
	return r, nil
}
func finishRecordedRun(r *RunRecorder, err *error) {
	*err = errors.Join(*err, r.Finish(*err))
	activeRun.CompareAndSwap(r, nil)
}

func processSource(pid uint32, base uint64) Source {
	s := Source{PID: pid, Base: fmt.Sprintf("0x%x", base)}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		s.StartTicks, err = parseStartTicks(string(stat))
	}
	if err != nil {
		s.IdentityError = err.Error()
	}
	if b, e := os.ReadFile("/proc/sys/kernel/random/boot_id"); e == nil {
		s.BootID = strings.TrimSpace(string(b))
	} else {
		s.IdentityError += "; boot_id: " + e.Error()
	}
	if b, e := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); e == nil {
		s.ProcessName = strings.TrimSpace(string(b))
	}
	if b, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					s.UID = fields[1]
				}
			}
		}
	}
	return s
}
func parseStartTicks(stat string) (string, error) {
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return "", errors.New("invalid proc stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) <= 19 {
		return "", errors.New("short proc stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", err
	}
	return fields[19], nil
}
func sourceKey(s Source) string { return fmt.Sprintf("%d-%s-%s", s.PID, s.StartTicks, s.BootID) }
func sameModule(a, b Source) bool {
	return a.PID != 0 && a.StartTicks != "" && a.BootID != "" && a.ModulePath != "" && a.Base != "" && a.IdentityError == "" && b.IdentityError == "" && sourceKey(a) == sourceKey(b) && a.ModulePath == b.ModulePath && a.Base == b.Base
}

func digestFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
func recordFile(path, kind, status, operation string, src Source, inputs []string, cause error, notes ...string) error {
	r := activeRun.Load()
	if r == nil {
		return cause
	}
	rel, err := filepath.Rel(r.Root, path)
	if err != nil {
		return errors.Join(cause, err)
	}
	a := Artifact{Path: rel, Kind: kind, Status: status, Operation: operation, Source: src, Inputs: inputs}
	if len(notes) > 0 {
		a.Note = notes[0]
	}
	if cause != nil {
		a.Status = "failed"
		a.Error = cause.Error()
	} else {
		a.SHA256, a.Size, err = digestFile(path)
		if err != nil {
			a.Status = "failed"
			a.Error = err.Error()
		}
	}
	return errors.Join(cause, err, r.record(a))
}
func writeArtifact(path string, data []byte, kind, status string, src Source) error {
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err == nil {
		err = os.WriteFile(path, data, 0644)
	}
	return recordFile(path, kind, status, "capture", src, nil, err)
}
func recordFailure(kind string, src Source, cause error) {
	if r := activeRun.Load(); r != nil {
		_ = r.record(Artifact{Kind: kind, Status: "failed", Source: src, Error: cause.Error(), Operation: "capture"})
	}
}

// findArtifact uses only the nearest manifest and verifies current file content.
// A damaged or stale manifest is an error, never permission to guess by filename.
func findArtifact(path string) (Artifact, bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Artifact{}, false, err
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		data, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if e == nil {
			var m RunManifest
			if e = json.Unmarshal(data, &m); e != nil {
				return Artifact{}, true, e
			}
			if m.SchemaVersion != 1 {
				return Artifact{}, true, errors.New("unsupported provenance schema")
			}
			rel, _ := filepath.Rel(dir, abs)
			for i := len(m.Artifacts) - 1; i >= 0; i-- {
				a := m.Artifacts[i]
				if a.Path != rel {
					continue
				}
				if a.Status == "failed" {
					return a, true, errors.New("artifact capture failed")
				}
				hash, _, e := digestFile(abs)
				if e != nil {
					return a, true, e
				}
				if hash != a.SHA256 {
					return a, true, errors.New("artifact hash mismatch")
				}
				return a, true, nil
			}
			return Artifact{}, false, nil
		}
		if !os.IsNotExist(e) {
			return Artifact{}, true, e
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return Artifact{}, false, nil
}

func repairInputs(paths ...string) ([]string, Source, error) {
	var ids []string
	var src Source
	for i, path := range paths {
		a, ok, err := findArtifact(path)
		if err != nil {
			return nil, src, err
		}
		if ok {
			ids = append(ids, a.ID)
			if i == 0 {
				src = a.Source
			}
		} else {
			hash, _, err := digestFile(path)
			if err != nil {
				return nil, src, err
			}
			ids = append(ids, "sha256:"+hash)
		}
	}
	return ids, src, nil
}

// recordedSymbols chooses maps only by verified process/module identity.
func recordedSymbols(soPath string) ([]InjectedSym, []string, error) {
	a, ok, err := findArtifact(soPath)
	if err != nil || !ok {
		return nil, nil, err
	}
	abs, _ := filepath.Abs(soPath)
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		data, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if e == nil {
			var m RunManifest
			if e = json.Unmarshal(data, &m); e != nil {
				return nil, nil, e
			}
			var candidates []Artifact
			for _, s := range m.Artifacts {
				if s.Kind == "jni_symbols" && s.Status == "complete" && sameModule(a.Source, s.Source) {
					candidates = append(candidates, s)
				}
			}
			if len(candidates) > 1 {
				return nil, nil, errors.New("ambiguous JNI symbol provenance")
			}
			if len(candidates) == 0 {
				return nil, nil, nil
			}
			s := candidates[0]
			clean := filepath.Clean(s.Path)
			if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
				return nil, nil, errors.New("symbol path escapes run directory")
			}
			path := filepath.Join(dir, clean)
			if _, _, e = findArtifact(path); e != nil {
				return nil, nil, e
			}
			syms, e := parseSymbolFile(path)
			return syms, []string{s.ID}, e
		}
		if !os.IsNotExist(e) {
			return nil, nil, e
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return nil, nil, nil
}

type dexIdentity struct {
	PID                uint32
	StartTicks, BootID string
	Begin              uint64
}

func dexID(pid uint32, begin uint64) dexIdentity {
	s := processSource(pid, begin)
	key := dexIdentity{pid, s.StartTicks, s.BootID, begin}
	if r := activeRun.Load(); r != nil {
		r.sources.LoadOrStore(key, s)
	}
	return key
}
func (k dexIdentity) source() Source {
	if r := activeRun.Load(); r != nil {
		if src, ok := r.sources.Load(k); ok {
			return src.(Source)
		}
	}
	s := Source{PID: k.PID, StartTicks: k.StartTicks, BootID: k.BootID, Base: fmt.Sprintf("0x%x", k.Begin)}
	current := processSource(k.PID, k.Begin)
	if current.StartTicks == k.StartTicks && current.BootID == k.BootID {
		s = current
	}
	if k.StartTicks == "" || k.BootID == "" {
		s.IdentityError = "process identity unavailable at capture"
	}
	return s
}
func dexArtifactPath(root string, k dexIdentity, size uint32, suffix string) string {
	identity := sha256.Sum256([]byte(sourceKey(k.source())))
	return filepath.Join(root, "dumps", fmt.Sprintf("pid_%d_%x", k.PID, identity[:8]), fmt.Sprintf("dex_%x_%x%s", k.Begin, size, suffix))
}

func repairOutputDir(dir string) string {
	if r := activeRun.Load(); r != nil {
		return filepath.Join(r.Root, "fix")
	}
	return filepath.Join(dir, "fix")
}
func routeSymbolFile(soPath, symbolPath string, syms []InjectedSym, legacyTarget string) ([]InjectedSym, []string, error) {
	symbols, known, err := findArtifact(symbolPath)
	if err != nil {
		return nil, nil, err
	}
	if known {
		if symbols.Kind != "jni_symbols" || symbols.Status != "complete" {
			return nil, nil, errors.New("not a complete JNI symbol artifact")
		}
		so, ok, err := findArtifact(soPath)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			return nil, nil, errors.New("recorded JNI symbols require SO provenance")
		}
		if !sameModule(so.Source, symbols.Source) {
			return nil, nil, nil
		}
		return syms, []string{symbols.ID}, nil
	}
	// Missing sidecar for a generated map must not turn its opaque ID into a
	// legacy wildcard that injects symbols into every module.
	if strings.HasPrefix(filepath.Base(symbolPath), "jni_symbols_") && len(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(symbolPath), "jni_symbols_"), ".txt")) == 24 {
		return nil, nil, errors.New("generated symbol map has no provenance")
	}
	if legacyTarget != "" && !soMatchesModule(filepath.Base(soPath), legacyTarget) {
		return nil, nil, nil
	}
	hash, _, err := digestFile(symbolPath)
	return syms, []string{"sha256:" + hash}, err
}
