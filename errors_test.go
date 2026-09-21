package adcore_test

import (
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
)

func TestClassifyCode(t *testing.T) {
	for _, tc := range []struct {
		code int
		want adcore.Kind
		ok   bool
	}{
		{0x2030, adcore.KindNotFound, true},      // ERROR_DS_NO_SUCH_OBJECT
		{0x2071, adcore.KindAlreadyExists, true}, // ERROR_DS_OBJ_STRING_NAME_EXISTS
		{0x2098, adcore.KindDenied, true},        // ERROR_DS_INSUFF_ACCESS_RIGHTS
		{0x200E, adcore.KindTransient, true},     // ERROR_DS_BUSY
		{0xDEAD, adcore.KindUnknown, false},      // unmapped fails closed
	} {
		got, ok := adcore.ClassifyCode(tc.code)
		if ok != tc.ok {
			t.Errorf("ClassifyCode(%#x) ok = %v, want %v", tc.code, ok, tc.ok)
		}
		if ok && got != tc.want {
			t.Errorf("ClassifyCode(%#x) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

func TestOnlyTransientIsRetryable(t *testing.T) {
	for k := adcore.KindUnknown; k <= adcore.KindUnsupported; k++ {
		want := k == adcore.KindTransient
		if got := k.Retryable(); got != want {
			t.Errorf("Kind(%v).Retryable() = %v, want %v", k, got, want)
		}
	}
}

func TestErrorMatchesSentinel(t *testing.T) {
	err := error(&adcore.Error{Kind: adcore.KindNotFound, Op: "OU.Get"})
	if !errors.Is(err, adcore.ErrNotFound) {
		t.Error("a KindNotFound Error should match ErrNotFound")
	}
	if errors.Is(err, adcore.ErrReplication) {
		t.Error("a KindNotFound Error must not match ErrReplication")
	}
}
