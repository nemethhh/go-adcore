package adcore

import "sync"

// KeyedMutex serializes writes to one target. Two writers naming different
// objects proceed concurrently, which is what keeps Terraform's parallel graph
// walk useful.
type KeyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyedEntry
}

type keyedEntry struct {
	mu   sync.Mutex
	refs int
}

// NewKeyedMutex returns a KeyedMutex ready for use.
func NewKeyedMutex() *KeyedMutex {
	return &KeyedMutex{m: make(map[string]*keyedEntry)}
}

// Lock blocks until key is available and returns the release function.
func (k *KeyedMutex) Lock(key string) (unlock func()) {
	k.mu.Lock()
	e, ok := k.m[key]
	if !ok {
		e = &keyedEntry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()

	var once sync.Once
	return func() {
		once.Do(func() {
			e.mu.Unlock()
			k.mu.Lock()
			e.refs--
			if e.refs == 0 {
				delete(k.m, key)
			}
			k.mu.Unlock()
		})
	}
}

// Size reports how many keys are currently held or waited on. Test support.
func (k *KeyedMutex) Size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}
