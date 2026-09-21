package adcore_test

import (
	"go/build"
	"strings"
	"testing"
)

// TestNoThirdPartyDependencies fails the build if any non-stdlib import enters
// this module's graph. go-adcore is the shared vocabulary for two backends and
// a Terraform provider; a dependency here is a dependency everywhere.
func TestNoThirdPartyDependencies(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("ImportDir: %v", err)
	}
	for _, imp := range append(pkg.Imports, pkg.TestImports...) {
		if strings.HasPrefix(imp, "github.com/nemethhh/go-adcore") {
			continue
		}
		if strings.Contains(imp, ".") {
			t.Errorf("third-party import not allowed in go-adcore: %q", imp)
		}
	}
}
