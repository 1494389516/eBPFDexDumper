package main

import (
	"eBPFDexDumper/internal/runmeta"
	"io"
)

type InspectIssue = runmeta.InspectIssue
type InspectReport = runmeta.InspectReport

func InspectDirectory(dir string) (InspectReport, error) { return runmeta.InspectDirectory(dir) }
func PrintInspectReport(w io.Writer, r InspectReport, asJSON bool) error {
	return runmeta.PrintInspectReport(w, r, asJSON)
}
