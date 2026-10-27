package ldapdir

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func fastRetries(t *testing.T) {
	saved := retryWaits
	retryWaits = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { retryWaits = saved })
}

func TestRetryGoesOnWhileBusy(t *testing.T) {
	fastRetries(t)
	calls := 0
	err := retry(context.Background(), func() error {
		calls++
		if calls < 3 {
			return ldap.NewError(ldap.LDAPResultBusy, errors.New("write conflict"))
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err %v after %d calls", err, calls)
	}
}

func TestRetryGivesUpWithTheLastError(t *testing.T) {
	fastRetries(t)
	calls := 0
	err := retry(context.Background(), func() error {
		calls++
		return ldap.NewError(ldap.LDAPResultUnavailable, errors.New("unavailable"))
	})
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) || calls != len(retryWaits)+1 {
		t.Fatalf("err %v after %d calls", err, calls)
	}
}

func TestRetryLeavesOtherErrorsAtOnce(t *testing.T) {
	fastRetries(t)
	calls := 0
	err := retry(context.Background(), func() error {
		calls++
		return ldap.NewError(ldap.LDAPResultConstraintViolation, errors.New("refused"))
	})
	if err == nil || calls != 1 {
		t.Fatalf("err %v after %d calls", err, calls)
	}
}

func TestRetryStopsWithTheContext(t *testing.T) {
	saved := retryWaits
	retryWaits = []time.Duration{time.Hour}
	t.Cleanup(func() { retryWaits = saved })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	err := retry(ctx, func() error {
		calls++
		return ldap.NewError(ldap.LDAPResultBusy, errors.New("busy"))
	})
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultBusy) || calls != 1 {
		t.Fatalf("err %v after %d calls", err, calls)
	}
}
