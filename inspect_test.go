package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func inspectFixture(t *testing.T) (string, RunManifest) {
	t.Helper()
	r := testRun(t, "dumpso")
	path := filepath.Join(r.Root, "dumps", "libsample.so")
	if err := writeArtifact(path, []byte("original"), "so", "complete", testSource()); err != nil {
		t.Fatal(err)
	}
	if err := r.Finish(nil); err != nil {
		t.Fatal(err)
	}
	activeRun.CompareAndSwap(r, nil)
	return r.Root, readManifest(t, r)
}
func storeInspectManifest(t *testing.T, root string, m RunManifest) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "manifest.json"), data)
}
func hasInspectCode(r InspectReport, code string) bool {
	for _, i := range r.Issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

func TestInspectCleanRunIsReadOnly(t *testing.T) {
	root, _ := inspectFixture(t)
	before := map[string][]byte{}
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			before[path], _ = os.ReadFile(path)
		}
		return nil
	})
	r, err := InspectDirectory(root)
	if err != nil || len(r.Issues) != 0 || r.VerifiedFiles != 1 || r.Runs != 1 {
		t.Fatalf("report: %+v %v", r, err)
	}
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("inspection changed file", path)
		}
	}
	var out bytes.Buffer
	if err := PrintInspectReport(&out, r, true); err != nil {
		t.Fatal(err)
	}
	var parsed InspectReport
	if err = json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.VerifiedFiles != 1 {
		t.Fatal("bad JSON report")
	}
}
func TestInspectDamagedArtifacts(t *testing.T) {
	for _, tc := range []struct{ name, code string }{
		{"modified", "hash_mismatch"}, {"missing", "missing_or_unsafe_file"},
		{"escape", "missing_or_unsafe_file"}, {"symlink", "missing_or_unsafe_file"},
		{"bad_json", "invalid_manifest"}, {"schema", "unsupported_schema"},
		{"duplicate", "duplicate_artifact_id"}, {"running", "run_running"},
		{"missing_journal", "missing_or_unsafe_journal"}, {"truncated_journal", "invalid_journal_record"},
		{"missing_event", "missing_journal_record"}, {"mismatch_event", "journal_manifest_mismatch"},
		{"reference", "unresolved_input"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, m := inspectFixture(t)
			path := filepath.Join(root, m.Artifacts[0].Path)
			switch tc.name {
			case "modified":
				writeTestFile(t, path, []byte("changed"))
			case "missing":
				os.Remove(path)
			case "escape":
				m.Artifacts[0].Path = "../outside"
				storeInspectManifest(t, root, m)
			case "symlink":
				os.Remove(path)
				if err := os.Symlink(filepath.Join(root, "manifest.json"), path); err != nil {
					t.Fatal(err)
				}
			case "bad_json":
				writeTestFile(t, filepath.Join(root, "manifest.json"), []byte("{"))
			case "schema":
				m.SchemaVersion = 999
				storeInspectManifest(t, root, m)
			case "duplicate":
				m.Artifacts = append(m.Artifacts, m.Artifacts[0])
				storeInspectManifest(t, root, m)
			case "running":
				m.Status = "running"
				storeInspectManifest(t, root, m)
			case "missing_journal":
				os.Remove(filepath.Join(root, "events.jsonl"))
			case "truncated_journal":
				writeTestFile(t, filepath.Join(root, "events.jsonl"), []byte("{\"id\":"))
			case "missing_event":
				writeTestFile(t, filepath.Join(root, "events.jsonl"), nil)
			case "mismatch_event":
				m.Artifacts[0].Note = "changed"
				storeInspectManifest(t, root, m)
			case "reference":
				m.Artifacts[0].Inputs = []string{"external:1"}
				storeInspectManifest(t, root, m)
			}
			r, err := InspectDirectory(root)
			if err != nil || !hasInspectCode(r, tc.code) {
				t.Fatalf("expected %s: %+v %v", tc.code, r, err)
			}
		})
	}
}
func TestInspectSymbolSourceMismatch(t *testing.T) {
	root, m := inspectFixture(t)
	a := m.Artifacts[0]
	a.ID = m.RunID + ":2"
	a.Kind = "jni_symbols"
	a.Source.PID++
	b := m.Artifacts[0]
	b.ID = m.RunID + ":3"
	b.Kind = "fixed_so"
	b.Inputs = []string{a.ID}
	m.Artifacts = append(m.Artifacts, a, b)
	storeInspectManifest(t, root, m)
	r, err := InspectDirectory(root)
	if err != nil || !hasInspectCode(r, "symbol_source_mismatch") {
		t.Fatalf("missed mismatch: %+v %v", r, err)
	}
}
func TestInspectParentResolvesCrossRunReference(t *testing.T) {
	root, m := inspectFixture(t)
	parent := filepath.Dir(root)
	r, err := NewRunRecorder(parent, "fixso")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.Root, "fixed.so")
	writeTestFile(t, path, []byte("fixed"))
	hash, size, err := digestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a := Artifact{Path: "fixed.so", Kind: "fixed_so", SHA256: hash, Size: size, Status: "complete", Source: m.Artifacts[0].Source, Inputs: []string{m.Artifacts[0].ID}}
	if err = r.record(a); err != nil {
		t.Fatal(err)
	}
	if err = r.Finish(nil); err != nil {
		t.Fatal(err)
	}
	report, err := InspectDirectory(parent)
	if err != nil || len(report.Issues) != 0 || report.Runs != 2 {
		t.Fatalf("parent inspection: %+v %v", report, err)
	}
	report, err = InspectDirectory(r.Root)
	if err != nil || !hasInspectCode(report, "unresolved_input") {
		t.Fatal("external reference not reported")
	}
}
func TestInspectLegacyAndInvalidDirectory(t *testing.T) {
	r, err := InspectDirectory(t.TempDir())
	if err != nil || !hasInspectCode(r, "no_manifest") {
		t.Fatal("legacy directory passed silently")
	}
	if _, err := InspectDirectory(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing root accepted")
	}
}
