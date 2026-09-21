package adcore_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nemethhh/go-adcore"
)

// Writes naming the same object serialize; writes naming different objects do
// not. A read-then-write delta has no compare-and-swap, so two concurrent
// updates to one identity would interleave and lose one side's changes.
func TestKeyedMutexSerializesOneKey(t *testing.T) {
	km := adcore.NewKeyedMutex()
	var inFlight, maxInFlight int32

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := km.Lock("guid:f1e2")
			defer unlock()
			n := atomic.AddInt32(&inFlight, 1)
			for {
				m := atomic.LoadInt32(&maxInFlight)
				if n <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&inFlight, -1)
		}()
	}
	wg.Wait()

	if maxInFlight != 1 {
		t.Errorf("max concurrent holders of one key = %d, want 1", maxInFlight)
	}
	if km.Size() != 0 {
		t.Errorf("KeyedMutex leaked %d entries after release", km.Size())
	}
}

func TestKeyedMutexAllowsDifferentKeys(t *testing.T) {
	km := adcore.NewKeyedMutex()
	a := km.Lock("guid:aaaa")
	done := make(chan struct{})
	go func() {
		b := km.Lock("guid:bbbb")
		b()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a lock on a different key blocked")
	}
	a()
}
