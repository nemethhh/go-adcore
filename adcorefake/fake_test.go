package adcorefake_test

import (
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adcore/adcorefake"
	"github.com/nemethhh/go-adcore/adcoretest"
)

// The fake is held to exactly the contract the real backends are. A fake that
// is more permissive than the thing it stands in for is worse than none: it
// green-lights code that fails on a domain.
func TestFakeConformance(t *testing.T) {
	adcoretest.RunDirectorySuite(t, func(t *testing.T) adcore.Directory {
		return adcorefake.New("DC=corp,DC=local")
	})
}
