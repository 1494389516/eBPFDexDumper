package runmeta

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

type InspectIssue struct {
	Code       string `json:"code"`
	Path       string `json:"path"`
	ArtifactID string `json:"artifact_id,omitempty"`
	Message    string `json:"message"`
}
type InspectReport struct {
	Root          string         `json:"root"`
	Runs          int            `json:"runs"`
	Artifacts     int            `json:"artifacts"`
	VerifiedFiles int            `json:"verified_files"`
	Issues        []InspectIssue `json:"issues"`
}

func (r *InspectReport) issue(code, path, id, message string) {
	r.Issues = append(r.Issues, InspectIssue{code, path, id, message})
}

// confinedPath rejects traversal and symlinks before any artifact is opened.
// Inspection never follows an artifact reference outside its owning run.
func confinedPath(root, rel string) (string, error) {
	clean := filepath.Clean(rel)
	if rel == "" || filepath.IsAbs(rel) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes run: %q", rel)
	}
	path := root
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		path = filepath.Join(path, part)
		st, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink is not inspected: %s", path)
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %s", path)
	}
	return path, nil
}
func validHash(s string) bool { b, err := hex.DecodeString(s); return err == nil && len(b) == 32 }

// InspectDirectory reads manifests and journals; it never repairs or writes.
func InspectDirectory(dir string) (InspectReport, error) {
	root, err := filepath.Abs(dir)
	r := InspectReport{Root: root, Issues: []InspectIssue{}}
	if err != nil {
		return r, err
	}
	st, err := os.Lstat(root)
	if err != nil {
		return r, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return r, fmt.Errorf("inspection root must be a real directory")
	}
	var manifests []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			r.issue("unreadable", path, "", walkErr.Error())
			return nil
		}
		if d.Name() == "manifest.json" && !d.IsDir() {
			manifests = append(manifests, path)
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	if len(manifests) == 0 {
		r.issue("no_manifest", root, "", "no manifest.json found; legacy files have no verifiable run records")
		return r, nil
	}
	type located struct {
		a    Artifact
		path string
		run  string
	}
	all := map[string]located{}
	runIDs := map[string]string{}
	var refs []located
	for _, path := range manifests {
		runRoot := filepath.Dir(path)
		if _, err := confinedPath(runRoot, "manifest.json"); err != nil {
			r.issue("unsafe_manifest", path, "", err.Error())
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			r.issue("unreadable", path, "", err.Error())
			continue
		}
		var m RunManifest
		if err = json.Unmarshal(data, &m); err != nil {
			r.issue("invalid_manifest", path, "", err.Error())
			continue
		}
		r.Runs++
		if m.SchemaVersion != 1 {
			r.issue("unsupported_schema", path, "", fmt.Sprintf("schema version %d", m.SchemaVersion))
			continue
		}
		if m.RunID == "" {
			r.issue("missing_run_id", path, "", "run ID is empty")
		} else if old, ok := runIDs[m.RunID]; ok {
			r.issue("duplicate_run_id", path, "", "also present in "+old)
		} else {
			runIDs[m.RunID] = path
		}
		switch m.Status {
		case "completed":
			if m.Ended == "" {
				r.issue("missing_end_time", path, "", "completed run has no end time")
			}
		case "running", "partial", "failed":
			r.issue("run_"+m.Status, path, "", "run is "+m.Status+": "+m.Error)
		default:
			r.issue("invalid_run_status", path, "", m.Status)
		}
		local := map[string]Artifact{}
		for _, a := range m.Artifacts {
			r.Artifacts++
			loc := located{a, path, runRoot}
			refs = append(refs, loc)
			if a.ID == "" {
				r.issue("missing_artifact_id", path, "", "artifact ID is empty")
			} else if old, ok := all[a.ID]; ok {
				r.issue("duplicate_artifact_id", path, a.ID, "also present in "+old.path)
			} else {
				all[a.ID] = loc
			}
			local[a.ID] = a
			switch a.Status {
			case "complete":
			case "partial", "degraded", "failed":
				r.issue("artifact_"+a.Status, path, a.ID, a.Error+a.Note)
			default:
				r.issue("invalid_artifact_status", path, a.ID, a.Status)
			}
			if a.Source.ReadBytes > a.Source.ExpectedBytes && a.Source.ExpectedBytes != 0 {
				r.issue("invalid_byte_counts", path, a.ID, "read bytes exceed expected bytes")
			}
			if a.Status == "complete" && a.Source.ExpectedBytes > 0 && a.Source.ReadBytes < a.Source.ExpectedBytes {
				r.issue("incomplete_read", path, a.ID, "complete artifact has missing source bytes")
			}
			if a.Source.PID != 0 && (a.Source.StartTicks == "" || a.Source.BootID == "" || a.Source.IdentityError != "") {
				r.issue("unknown_process_identity", path, a.ID, "PID reuse cannot be checked: "+a.Source.IdentityError)
			}
			if a.Kind == "jni_symbols" && (a.Source.PID == 0 || a.Source.ModulePath == "" || a.Source.Base == "") {
				r.issue("missing_module_identity", path, a.ID, "JNI map has no complete module identity")
			}
			// A failed capture may have no output file at all.
			if a.Status == "failed" {
				continue
			}
			file, e := confinedPath(runRoot, a.Path)
			if e != nil {
				r.issue("missing_or_unsafe_file", path, a.ID, e.Error())
				continue
			}
			hash, size, e := DigestFile(file)
			if e != nil {
				r.issue("unreadable", file, a.ID, e.Error())
				continue
			}
			valid := true
			if !validHash(a.SHA256) || hash != a.SHA256 {
				r.issue("hash_mismatch", file, a.ID, "file SHA-256 differs from manifest or expected hash is invalid")
				valid = false
			}
			if size != a.Size {
				r.issue("size_mismatch", file, a.ID, fmt.Sprintf("actual %d, recorded %d", size, a.Size))
				valid = false
			}
			if valid {
				r.VerifiedFiles++
			}
			if (a.Kind == "fixed_so" || a.Kind == "fixed_dex") && len(a.Inputs) == 0 {
				r.issue("missing_lineage", path, a.ID, "repair has no input references")
			}
		}
		inspectJournal(&r, runRoot, local)
	}
	for _, loc := range refs {
		for _, id := range loc.a.Inputs {
			if strings.HasPrefix(id, "sha256:") {
				if !validHash(strings.TrimPrefix(id, "sha256:")) {
					r.issue("invalid_input_hash", loc.path, loc.a.ID, id)
				}
				continue
			}
			input, ok := all[id]
			if !ok {
				r.issue("unresolved_input", loc.path, loc.a.ID, "input "+id+" is missing or outside inspected directory")
				continue
			}
			if id == loc.a.ID {
				r.issue("self_reference", loc.path, loc.a.ID, "artifact references itself")
			}
			if input.a.Status == "failed" {
				r.issue("failed_input", loc.path, loc.a.ID, "input "+id+" failed")
			}
			if loc.a.Kind == "fixed_so" && input.a.Kind == "jni_symbols" && !SameModule(loc.a.Source, input.a.Source) {
				r.issue("symbol_source_mismatch", loc.path, loc.a.ID, "JNI input belongs to a different or unknown process/module")
			}
		}
	}
	sort.SliceStable(r.Issues, func(i, j int) bool {
		a, b := r.Issues[i], r.Issues[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.ArtifactID != b.ArtifactID {
			return a.ArtifactID < b.ArtifactID
		}
		return a.Code < b.Code
	})
	return r, nil
}

func inspectJournal(r *InspectReport, root string, artifacts map[string]Artifact) {
	path, err := confinedPath(root, "events.jsonl")
	if err != nil {
		r.issue("missing_or_unsafe_journal", root, "", err.Error())
		return
	}
	f, err := os.Open(path)
	if err != nil {
		r.issue("unreadable", path, "", err.Error())
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 16*1024*1024)
	seen := map[string]bool{}
	line := 0
	for scanner.Scan() {
		line++
		var a Artifact
		if err := json.Unmarshal(scanner.Bytes(), &a); err != nil {
			r.issue("invalid_journal_record", path, "", fmt.Sprintf("line %d: %v", line, err))
			continue
		}
		if seen[a.ID] {
			r.issue("duplicate_journal_id", path, a.ID, fmt.Sprintf("line %d", line))
		}
		seen[a.ID] = true
		expected, ok := artifacts[a.ID]
		if !ok {
			r.issue("journal_only_artifact", path, a.ID, "record absent from manifest")
		} else if !reflect.DeepEqual(expected, a) {
			r.issue("journal_manifest_mismatch", path, a.ID, "journal and manifest disagree")
		}
	}
	if err := scanner.Err(); err != nil {
		r.issue("journal_read_error", path, "", err.Error())
	}
	for id := range artifacts {
		if !seen[id] {
			r.issue("missing_journal_record", path, id, "manifest entry absent from journal")
		}
	}
}

// PrintInspectReport shares JSON/text output between desktop and Android CLIs.
func PrintInspectReport(w io.Writer, r InspectReport, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	if _, err := fmt.Fprintf(w, "Runs: %d, artifacts: %d, verified files: %d, issues: %d\n", r.Runs, r.Artifacts, r.VerifiedFiles, len(r.Issues)); err != nil {
		return err
	}
	for _, issue := range r.Issues {
		if _, err := fmt.Fprintf(w, "[%s] %s %s: %s\n", issue.Code, issue.Path, issue.ArtifactID, issue.Message); err != nil {
			return err
		}
	}
	return nil
}
