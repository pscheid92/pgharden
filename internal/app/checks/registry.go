package checks

import (
	"github.com/pscheid92/pgharden/internal/app/checks/section1"
	"github.com/pscheid92/pgharden/internal/app/checks/section2"
	"github.com/pscheid92/pgharden/internal/app/checks/section3"
	"github.com/pscheid92/pgharden/internal/app/checks/section4"
	"github.com/pscheid92/pgharden/internal/app/checks/section5"
	"github.com/pscheid92/pgharden/internal/app/checks/section6"
	"github.com/pscheid92/pgharden/internal/app/checks/section7"
	"github.com/pscheid92/pgharden/internal/app/checks/section8"
	"github.com/pscheid92/pgharden/internal/domain"
)

func All() []domain.Check {
	var all []domain.Check
	all = append(all, section1.Checks()...)
	all = append(all, section2.Checks()...)
	all = append(all, section3.Checks()...)
	all = append(all, section4.Checks()...)
	all = append(all, section5.Checks()...)
	all = append(all, section6.Checks()...)
	all = append(all, section7.Checks()...)
	all = append(all, section8.Checks()...)
	domain.SortChecks(all)
	return all
}
