package checker

import (
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Check)
)

// Register adds a check to the global registry. Called from init() in check files.
func Register(c Check) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[c.ID()] = c
}

// All returns all registered checks sorted by ID.
func All() []Check {
	registryMu.RLock()
	defer registryMu.RUnlock()

	checks := make([]Check, 0, len(registry))
	for _, c := range registry {
		checks = append(checks, c)
	}
	sort.Slice(checks, func(i, j int) bool {
		return CompareCheckIDs(checks[i].ID(), checks[j].ID()) < 0
	})
	return checks
}

// Get returns a specific check by ID, or nil if not found.
func Get(id string) Check {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[id]
}

// CompareCheckIDs compares two dotted-number check IDs (e.g., "1.4.3" vs "1.10").
func CompareCheckIDs(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := max(len(partsB), len(partsA))

	for i := 0; i < maxLen; i++ {
		var na, nb int
		if i < len(partsA) {
			na, _ = strconv.Atoi(partsA[i])
		}
		if i < len(partsB) {
			nb, _ = strconv.Atoi(partsB[i])
		}
		if na != nb {
			return na - nb
		}
	}
	return 0
}
