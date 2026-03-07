package cli

import (
	"github.com/pgharden/pgharden/internal/checker"
	"github.com/pgharden/pgharden/internal/checks/section1"
	"github.com/pgharden/pgharden/internal/checks/section2"
	"github.com/pgharden/pgharden/internal/checks/section3"
	"github.com/pgharden/pgharden/internal/checks/section4"
	"github.com/pgharden/pgharden/internal/checks/section5"
	"github.com/pgharden/pgharden/internal/checks/section6"
	"github.com/pgharden/pgharden/internal/checks/section7"
	"github.com/pgharden/pgharden/internal/checks/section8"
)

func loadChecks() []checker.Check {
	var checks []checker.Check
	checks = append(checks, section1.Checks()...)
	checks = append(checks, section2.Checks()...)
	checks = append(checks, section3.Checks()...)
	checks = append(checks, section4.Checks()...)
	checks = append(checks, section5.Checks()...)
	checks = append(checks, section6.Checks()...)
	checks = append(checks, section7.Checks()...)
	checks = append(checks, section8.Checks()...)
	checker.SortChecks(checks)
	return checks
}
