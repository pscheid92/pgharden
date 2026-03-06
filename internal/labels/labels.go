package labels

// LabelSet holds titles and descriptions for all checks in a language.
type LabelSet struct {
	Sections map[string]string      // section ID → title
	Checks   map[string]CheckLabel  // check ID → label
}

// CheckLabel holds the display text for a single check.
type CheckLabel struct {
	Title       string
	Description string
	Manual      bool
}

var languages = map[string]*LabelSet{}

// RegisterLanguage adds a language's labels.
func RegisterLanguage(lang string, ls *LabelSet) {
	languages[lang] = ls
}

func get(lang string) *LabelSet {
	if ls, ok := languages[lang]; ok {
		return ls
	}
	if ls, ok := languages["en_US"]; ok {
		return ls
	}
	return &LabelSet{Sections: map[string]string{}, Checks: map[string]CheckLabel{}}
}

// SectionTitle returns the localized section title.
func SectionTitle(lang, sectionID string) string {
	ls := get(lang)
	if t, ok := ls.Sections[sectionID]; ok {
		return t
	}
	return "Section " + sectionID
}

// CheckTitle returns the localized check title.
func CheckTitle(lang, checkID string) string {
	ls := get(lang)
	if c, ok := ls.Checks[checkID]; ok {
		return c.Title
	}
	return "Check " + checkID
}

// CheckDescription returns the localized check description.
func CheckDescription(lang, checkID string) string {
	ls := get(lang)
	if c, ok := ls.Checks[checkID]; ok {
		return c.Description
	}
	return ""
}

// IsManual returns whether a check is manual-only.
func IsManual(lang, checkID string) bool {
	ls := get(lang)
	if c, ok := ls.Checks[checkID]; ok {
		return c.Manual
	}
	return false
}
