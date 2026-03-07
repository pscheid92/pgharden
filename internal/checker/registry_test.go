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

func TestSortChecks(t *testing.T) {
	checks := []Check{
		&SettingCheck{CheckID: "2.1"},
		&SettingCheck{CheckID: "1.10"},
		&SettingCheck{CheckID: "1.2"},
		&SettingCheck{CheckID: "1.1"},
		&SettingCheck{CheckID: "3.1.2"},
	}

	SortChecks(checks)

	for i := 1; i < len(checks); i++ {
		if CompareCheckIDs(checks[i-1].ID(), checks[i].ID()) > 0 {
			t.Errorf("checks not sorted: %s before %s", checks[i-1].ID(), checks[i].ID())
		}
	}
}
