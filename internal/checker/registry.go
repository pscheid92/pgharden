package checker

import (
	"sort"
	"strconv"
	"strings"
)

// SortChecks sorts checks by their dotted-number IDs.
func SortChecks(checks []Check) {
	sort.Slice(checks, func(i, j int) bool {
		return CompareCheckIDs(checks[i].ID(), checks[j].ID()) < 0
	})
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
