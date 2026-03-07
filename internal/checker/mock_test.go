package checker

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
)

func newMockDB(t *testing.T) pgxmock.PgxConnIface {
	t.Helper()
	mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("creating pgxmock: %v", err)
	}
	t.Cleanup(func() { _ = mock.Close(context.Background()) })
	return mock
}
