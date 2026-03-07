package checker

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type SettingCheck struct {
	CheckID    string
	Setting    string            // PostgreSQL setting name (used in SHOW <setting>)
	Expected   string            // Expected value (interpretation depends on Comparator)
	Comparator string            // "eq" (default), "neq", "contains", "oneof"
	Sev        Severity          // Severity level for failures
	Reqs       CheckRequirements // Requirements for this check
	SuccessMsg string            // Custom success message (optional; auto-generated if empty)
	FailureMsg string            // Custom failure message (optional; auto-generated if empty)
}

func (c *SettingCheck) ID() string {
	return c.CheckID
}

func (c *SettingCheck) Requirements() CheckRequirements {
	return c.Reqs
}

func (c *SettingCheck) Run(ctx context.Context, env *Environment) (*CheckResult, error) {
	val, err := ShowSetting(ctx, env.DB, c.Setting)
	if errors.Is(err, ErrPermissionDenied) {
		return SkippedPermission(c.Setting), nil
	}
	if err != nil {
		return nil, err
	}

	result := &CheckResult{Severity: c.Sev}

	if c.compare(val) {
		msg := c.SuccessMsg
		if msg == "" {
			msg = fmt.Sprintf("%s is correctly set to '%s'", c.Setting, val)
		}
		result.Pass(msg)
		return result, nil
	}

	msg := c.FailureMsg
	if msg == "" {
		msg = fmt.Sprintf("%s is '%s', expected '%s'", c.Setting, val, c.Expected)
	}
	result.Fail("FAILURE", msg)
	return result, nil
}

func (c *SettingCheck) compare(val string) bool {
	switch c.Comparator {
	case "neq":
		return val != c.Expected
	case "contains":
		return strings.Contains(val, c.Expected)
	case "oneof":
		for candidate := range strings.SplitSeq(c.Expected, ",") {
			if val == strings.TrimSpace(candidate) {
				return true
			}
		}
		return false
	default: // "eq" or empty
		return val == c.Expected
	}
}
