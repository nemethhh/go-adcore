// Package adcoretest asserts the guarantees an adcore.Directory must uphold,
// against any implementation.
//
// These were once enforced structurally: one core implemented them and no
// backend could opt out. With backends in separate modules that is no longer
// possible, so the guarantee is behavioural and lives here. A backend that
// does not run RunDirectorySuite is not a conforming implementation.
package adcoretest
