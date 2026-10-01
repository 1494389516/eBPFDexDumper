//go:build !arm64

package main

import (
	"flag"
	"fmt"
	"os"
)

// Desktop builds expose only offline inspection; capture remains ARM64-only.
func main() { os.Exit(inspectMain(os.Args[1:])) }
func inspectMain(args []string) int {
	if len(args) == 0 || args[0] != "inspect" {
		fmt.Fprintln(os.Stderr, "Usage: eBPFDexDumper inspect --dir <output-directory> [--json]")
		return 2
	}
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dir := flags.String("dir", "", "Run directory or parent containing multiple runs")
	flags.StringVar(dir, "d", "", "Alias for --dir")
	asJSON := flags.Bool("json", false, "Print JSON report to stdout")
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *dir == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "--dir is required; unexpected positional arguments are not accepted")
		return 2
	}
	report, err := InspectDirectory(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err = PrintInspectReport(os.Stdout, report, *asJSON); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(report.Issues) > 0 {
		return 1
	}
	return 0
}
