package bodyclose

import (
	"flag"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
)

// ConsumptionAnalyzer is a variant of Analyzer with consumption checking enabled
var ConsumptionAnalyzer = &analysis.Analyzer{
	Name: "bodyconsumption",
	Doc:  "checks whether HTTP response body is closed and consumed successfully",
	Run:  runWithConsumption,
	Requires: []*analysis.Analyzer{
		buildssa.Analyzer,
	},
	Flags: func() flag.FlagSet {
		fs := flag.NewFlagSet("bodyconsumption", flag.ExitOnError)
		fs.Bool("check-consumption", true, "also check that response body is consumed")
		return *fs
	}(),
}

// runWithConsumption runs the analyzer with consumption checking enabled
func runWithConsumption(pass *analysis.Pass) (interface{}, error) {
	r := runner{
		pass:             pass,
		checkConsumption: true,
	}

	return runWithRunner(pass, &r)
}
