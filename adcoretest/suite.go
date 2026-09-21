package adcoretest

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/nemethhh/go-adcore"
)

// RunDirectorySuite asserts every module-boundary guarantee against the
// implementation newDirectory returns. newDirectory is called once per
// subtest and must return a Directory over an empty domain.
func RunDirectorySuite(t *testing.T, newDirectory func(*testing.T) adcore.Directory) {
	t.Helper()
	t.Run("CreateReturnsWhatGetReturns", func(t *testing.T) { testReadBack(t, newDirectory) })
	t.Run("DeleteVerifiesAbsence", func(t *testing.T) { testDeleteVerifies(t, newDirectory) })
	t.Run("NotFoundOnDeleteIsSuccess", func(t *testing.T) { testDeleteIdempotent(t, newDirectory) })
	t.Run("WritesToOneIdentitySerialize", func(t *testing.T) { testWriteSerialization(t, newDirectory) })
	t.Run("SearchErrorsRatherThanTruncating", func(t *testing.T) { testSearchLimit(t, newDirectory) })
	t.Run("RenameAndMoveNeverReplace", func(t *testing.T) { testRenameMoveInPlace(t, newDirectory) })
}

// mustCreateOU fails the test on anything but success or a replication wait.
// KindReplication means the write landed and only the wait timed out, so the
// model it returns is still the object that was created.
func mustCreateOU(t *testing.T, d adcore.Directory, spec adcore.OUSpec) *adcore.OU {
	t.Helper()
	ou, err := d.OU.Create(context.Background(), spec)
	if err != nil && !errors.Is(err, adcore.ErrReplication) {
		t.Fatalf("Create %q: %v", spec.Name, err)
	}
	if ou == nil {
		t.Fatalf("Create %q returned no model", spec.Name)
	}
	return ou
}

// An inconsistent result after apply must be impossible by construction:
// Create returns the result of the same read Get performs.
func testReadBack(t *testing.T, newDirectory func(*testing.T) adcore.Directory) {
	ctx := context.Background()
	d := newDirectory(t)
	defer d.Close()

	created := mustCreateOU(t, d, adcore.OUSpec{Name: "Staff", Container: d.DNC})

	got, err := d.OU.Get(ctx, adcore.ByGUID(created.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if *got != *created {
		t.Errorf("Create returned %+v but Get returns %+v", *created, *got)
	}
}

// Delete returns nil only after a re-read confirms the object is gone.
func testDeleteVerifies(t *testing.T, newDirectory func(*testing.T) adcore.Directory) {
	ctx := context.Background()
	d := newDirectory(t)
	defer d.Close()

	ou := mustCreateOU(t, d, adcore.OUSpec{Name: "Doomed", Container: d.DNC})
	if err := d.OU.Delete(ctx, adcore.ByGUID(ou.GUID), adcore.DeleteOptions{Unprotect: true}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := d.OU.Get(ctx, adcore.ByGUID(ou.GUID)); !errors.Is(err, adcore.ErrNotFound) {
		t.Errorf("Delete returned nil but the object is still readable: %v", err)
	}
}

// A not-found during Delete is success: the desired state is already true.
func testDeleteIdempotent(t *testing.T, newDirectory func(*testing.T) adcore.Directory) {
	ctx := context.Background()
	d := newDirectory(t)
	defer d.Close()

	err := d.OU.Delete(ctx, adcore.ByGUID("00000000-0000-0000-0000-000000000000"), adcore.DeleteOptions{})
	if err != nil && !errors.Is(err, adcore.ErrNotFound) {
		t.Fatalf("Delete of a missing object: %v", err)
	}
}

// A read-then-write delta has no compare-and-swap, so writes naming the same
// object must serialize or one side's changes are lost.
func testWriteSerialization(t *testing.T, newDirectory func(*testing.T) adcore.Directory) {
	ctx := context.Background()
	d := newDirectory(t)
	defer d.Close()

	ou := mustCreateOU(t, d, adcore.OUSpec{Name: "Contended", Container: d.DNC})
	id := adcore.ByGUID(ou.GUID)

	const writers = 6
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = d.OU.Update(ctx, id, adcore.OUSpec{
				Name:        "Contended",
				Container:   d.DNC,
				Description: adcore.String("writer"),
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil && !errors.Is(err, adcore.ErrReplication) {
			t.Errorf("writer %d: %v", i, err)
		}
	}
	final, err := d.OU.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after concurrent updates: %v", err)
	}
	if final.Description != "writer" {
		t.Errorf("Description = %q after serialized writes, want %q", final.Description, "writer")
	}
}

// A search matching more than its limit errors with KindTooManyResults rather
// than silently returning a truncated set.
func testSearchLimit(t *testing.T, newDirectory func(*testing.T) adcore.Directory) {
	ctx := context.Background()
	d := newDirectory(t)
	defer d.Close()

	for _, name := range []string{"L1", "L2", "L3"} {
		mustCreateOU(t, d, adcore.OUSpec{Name: name, Container: d.DNC})
	}

	_, err := d.OU.Search(ctx, adcore.Query{SearchBase: d.DNC, SizeLimit: 2})
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindTooManyResults {
		t.Fatalf("want KindTooManyResults, got %#v", err)
	}
}

// Nothing forces a replace. A rename and a move are in-place updates, because
// deleting and recreating an AD object destroys its SID and every ACL naming
// it. The objectGUID must survive both.
func testRenameMoveInPlace(t *testing.T, newDirectory func(*testing.T) adcore.Directory) {
	ctx := context.Background()
	d := newDirectory(t)
	defer d.Close()

	parent := mustCreateOU(t, d, adcore.OUSpec{Name: "Parent", Container: d.DNC})
	child := mustCreateOU(t, d, adcore.OUSpec{Name: "Before", Container: d.DNC})

	moved, err := d.OU.Update(ctx, adcore.ByGUID(child.GUID), adcore.OUSpec{
		Name:      "After",
		Container: parent.DN,
	})
	if err != nil && !errors.Is(err, adcore.ErrReplication) {
		t.Fatalf("Update (rename + move): %v", err)
	}
	if moved.GUID != child.GUID {
		t.Errorf("objectGUID changed across rename+move: %q -> %q; the object was replaced", child.GUID, moved.GUID)
	}
	if moved.Name != "After" {
		t.Errorf("Name = %q, want %q", moved.Name, "After")
	}
	if moved.Container != parent.DN {
		t.Errorf("Container = %q, want %q", moved.Container, parent.DN)
	}
}
