package labels

import "testing"

func TestSectionTitle(t *testing.T) {
	got := SectionTitle("1")
	if got != "Installation and Patches" {
		t.Errorf("SectionTitle(1) = %q", got)
	}
}

func TestSectionTitleFallback(t *testing.T) {
	got := SectionTitle("99")
	if got != "Section 99" {
		t.Errorf("SectionTitle(99) = %q, want 'Section 99'", got)
	}
}

func TestCheckTitle(t *testing.T) {
	got := CheckTitle("1.1")
	if got == "" || got == "Check 1.1" {
		t.Errorf("CheckTitle(1.1) = %q, expected a real title", got)
	}
}

func TestCheckTitleFallback(t *testing.T) {
	got := CheckTitle("99.99")
	if got != "Check 99.99" {
		t.Errorf("CheckTitle(99.99) = %q, want 'Check 99.99'", got)
	}
}

func TestCheckDescription(t *testing.T) {
	got := CheckDescription("1.1")
	if got == "" {
		t.Error("CheckDescription(1.1) is empty, expected content")
	}
}

func TestCheckDescriptionMissing(t *testing.T) {
	got := CheckDescription("99.99")
	if got != "" {
		t.Errorf("CheckDescription(99.99) = %q, want empty", got)
	}
}
