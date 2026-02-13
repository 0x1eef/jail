package test

import (
	"testing"

	"git.hardenedbsd.org/0x1eef/jail"
)

func TestNew(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
}

func TestRemove(t *testing.T) {
	j := newJail(t)
	if err := j.Remove(); err != nil {
		t.Fatalf("remove jail fail: %v", err)
	}
}

func TestLiving(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	jails, err := jail.Living()
	if err != nil || len(jails) == 0 {
		t.Fatalf("expected at least one jail")
	}
}

func TestAll(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	jails, err := jail.All()
	if err != nil || len(jails) == 0 {
		t.Fatalf("expected at least one jail")
	}
}

func TestDying(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	jails, err := jail.Dying()
	if err != nil || len(jails) > 0 {
		t.Fatalf("expected zero jails")
	}
}

func newJail(t *testing.T) *jail.Jail {
	j, err := jail.NewJail("/tmp/jail")
	if err != nil {
		t.Fatalf("new jail fail: %v", err)
	}
	return j
}
