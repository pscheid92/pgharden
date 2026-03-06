package checker

import "testing"

func TestCompareCheckIDs(t *testing.T) {
	tests := []struct {
		a, b string
		want int // negative, zero, positive
	}{
		{"1.1", "1.2", -1},
		{"1.2", "1.1", 1},
		{"1.1", "1.1", 0},
		{"1.9", "1.10", -1},
		{"2.1", "1.9", 1},
		{"1.4.3", "1.4.10", -1},
		{"1.4.3", "1.5", -1},
		{"3.1.2", "3.2", -1},
		{"10.1", "2.1", 1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			got := CompareCheckIDs(tt.a, tt.b)
			if tt.want < 0 && got >= 0 {
				t.Errorf("CompareCheckIDs(%q, %q) = %d, want negative", tt.a, tt.b, got)
			} else if tt.want > 0 && got <= 0 {
				t.Errorf("CompareCheckIDs(%q, %q) = %d, want positive", tt.a, tt.b, got)
			} else if tt.want == 0 && got != 0 {
				t.Errorf("CompareCheckIDs(%q, %q) = %d, want 0", tt.a, tt.b, got)
			}
		})
	}
}

func TestRegisterAndGet(t *testing.T) {
	// Save and restore registry state.
	registryMu.Lock()
	origRegistry := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer func() {
		registryMu.Lock()
		registry = origRegistry
		registryMu.Unlock()
	}()

	c := &SettingCheck{CheckID: "99.1", Setting: "test", Expected: "on"}
	Register(c)

	got := Get("99.1")
	if got == nil {
		t.Fatal("Get returned nil for registered check")
	}
	if got.ID() != "99.1" {
		t.Errorf("got ID %q, want %q", got.ID(), "99.1")
	}

	if Get("99.99") != nil {
		t.Error("Get returned non-nil for unregistered check")
	}
}

func TestAllSorted(t *testing.T) {
	registryMu.Lock()
	origRegistry := registry
	registry = make(map[string]Check)
	registryMu.Unlock()
	defer func() {
		registryMu.Lock()
		registry = origRegistry
		registryMu.Unlock()
	}()

	ids := []string{"2.1", "1.10", "1.2", "1.1", "3.1.2"}
	for _, id := range ids {
		Register(&SettingCheck{CheckID: id, Setting: "x", Expected: "y"})
	}

	all := All()
	if len(all) != len(ids) {
		t.Fatalf("got %d checks, want %d", len(all), len(ids))
	}

	for i := 1; i < len(all); i++ {
		if CompareCheckIDs(all[i-1].ID(), all[i].ID()) > 0 {
			t.Errorf("checks not sorted: %s before %s", all[i-1].ID(), all[i].ID())
		}
	}
}
