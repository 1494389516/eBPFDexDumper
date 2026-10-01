package main

import (
	"eBPFDexDumper/internal/runmeta"
	"flag"
	"fmt"
	"os"
)

// Standalone inspector has no BPF, cgo or Android dependency.
func main() { os.Exit(inspectMain(os.Args[1:])) }
func inspectMain(args []string) int {
	if len(args) > 0 && args[0] == "inspect" {
		args = args[1:]
	}
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	dir := flags.String("dir", "", "Run directory or parent containing multiple runs")
	flags.StringVar(dir, "d", "", "Alias for --dir")
	asJSON := flags.Bool("json", false, "Print JSON report to stdout")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *dir == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "--dir is required; unexpected positional arguments are not accepted")
		return 2
	}
	report, err := runmeta.InspectDirectory(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err = runmeta.PrintInspectReport(os.Stdout, report, *asJSON); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(report.Issues) > 0 {
		return 1
	}
	return 0
}
