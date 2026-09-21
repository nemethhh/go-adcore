package adcore_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nemethhh/go-adcore"
)

func TestSecretNeverPrints(t *testing.T) {
	s := adcore.NewSecret("hunter2")
	for _, verb := range []string{"%v", "%s", "%d", "%#v", "%+v"} {
		got := fmt.Sprintf(verb, s)
		if strings.Contains(got, "hunter2") {
			t.Errorf("verb %s leaked the plaintext: %q", verb, got)
		}
	}
}

func TestSecretMarshalAlwaysFails(t *testing.T) {
	type wrapper struct{ Password adcore.Secret }
	if _, err := json.Marshal(wrapper{adcore.NewSecret("hunter2")}); err == nil {
		t.Fatal("a struct walk marshalled a Secret; it must be a loud error")
	}
}

func TestRevealSecret(t *testing.T) {
	if got := adcore.RevealSecret(adcore.NewSecret("hunter2")); got != "hunter2" {
		t.Errorf("RevealSecret = %q, want %q", got, "hunter2")
	}
	if !adcore.NewSecret("").IsZero() {
		t.Error("empty secret should report IsZero")
	}
}
