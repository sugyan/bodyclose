package bodyclose_test

import (
	"testing"

	"github.com/timakin/bodyclose/passes/bodyclose"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestConsumption(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, bodyclose.ConsumptionAnalyzer, "consumption")
}
