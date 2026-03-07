package postgres

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
)

func newMock(t *testing.T) pgxmock.PgxConnIface {
	t.Helper()
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("creating pgxmock: %v", err)
	}
	t.Cleanup(func() { _ = mock.Close(context.Background()) })
	return mock
}

func TestDetectPrivileges_Superuser(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolsuper"}).AddRow(true))
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT COUNT.*pg_monitor").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	p, err := DetectPrivileges(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsSuperuser {
		t.Error("expected IsSuperuser=true")
	}
	if p.IsRDSSuperuser {
		t.Error("expected IsRDSSuperuser=false")
	}
	if p.IsPGMonitor {
		t.Error("expected IsPGMonitor=false")
	}
}

func TestDetectPrivileges_NonSuperuser(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolsuper"}).AddRow(false))
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT COUNT.*pg_monitor").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	p, err := DetectPrivileges(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if p.IsSuperuser {
		t.Error("expected IsSuperuser=false")
	}
}

func TestDetectPrivileges_RDSSuperuser(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolsuper"}).AddRow(false))
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COUNT.*pg_monitor").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))

	p, err := DetectPrivileges(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if p.IsSuperuser {
		t.Error("expected IsSuperuser=false")
	}
	if !p.IsRDSSuperuser {
		t.Error("expected IsRDSSuperuser=true")
	}
}

func TestDetectPrivileges_PGMonitor(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnRows(pgxmock.NewRows([]string{"rolsuper"}).AddRow(false))
	mock.ExpectQuery("SELECT COUNT.*rds_superuser").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT COUNT.*pg_monitor").
		WillReturnRows(pgxmock.NewRows([]string{"count"}).AddRow(1))

	p, err := DetectPrivileges(context.Background(), mock)
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsPGMonitor {
		t.Error("expected IsPGMonitor=true")
	}
}

func TestDetectPrivileges_QueryError(t *testing.T) {
	mock := newMock(t)
	mock.ExpectQuery("SELECT rolsuper FROM pg_roles").
		WillReturnError(context.DeadlineExceeded)

	_, err := DetectPrivileges(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error")
	}
}
