package labels

import "testing"

func TestSectionTitle(t *testing.T) {
	// en_US is registered via init() in en_us.go
	got := SectionTitle("en_US", "1")
	if got != "Installation and Patches" {
		t.Errorf("SectionTitle(en_US, 1) = %q", got)
	}
}

func TestSectionTitleFallback(t *testing.T) {
	got := SectionTitle("en_US", "99")
	if got != "Section 99" {
		t.Errorf("SectionTitle(en_US, 99) = %q, want 'Section 99'", got)
	}
}

func TestSectionTitleUnknownLang(t *testing.T) {
	// Should fall back to en_US
	got := SectionTitle("xx_XX", "1")
	if got != "Installation and Patches" {
		t.Errorf("SectionTitle(xx_XX, 1) = %q, want en_US fallback", got)
	}
}

func TestCheckTitle(t *testing.T) {
	got := CheckTitle("en_US", "1.1")
	if got == "" || got == "Check 1.1" {
		t.Errorf("CheckTitle(en_US, 1.1) = %q, expected a real title", got)
	}
}

func TestCheckTitleFallback(t *testing.T) {
	got := CheckTitle("en_US", "99.99")
	if got != "Check 99.99" {
		t.Errorf("CheckTitle(en_US, 99.99) = %q, want 'Check 99.99'", got)
	}
}

func TestCheckDescription(t *testing.T) {
	got := CheckDescription("en_US", "1.1")
	if got == "" {
		t.Error("CheckDescription(en_US, 1.1) is empty, expected content")
	}
}

func TestCheckDescriptionMissing(t *testing.T) {
	got := CheckDescription("en_US", "99.99")
	if got != "" {
		t.Errorf("CheckDescription(en_US, 99.99) = %q, want empty", got)
	}
}

func TestIsManual(t *testing.T) {
	// 1.1 is marked as manual in en_us.go
	if !IsManual("en_US", "1.1") {
		t.Error("IsManual(en_US, 1.1) = false, want true")
	}
	// 1.2 is not manual
	if IsManual("en_US", "1.2") {
		t.Error("IsManual(en_US, 1.2) = true, want false")
	}
}
