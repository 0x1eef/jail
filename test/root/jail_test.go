package test

import (
	"log"
	"os"
	"os/user"
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
	if err != nil {
		t.Fatalf("%v", err)
	} else if len(jails) == 0 {
		t.Fatalf("expected at least one jail")
	}
}

func TestAll(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	jails, err := jail.All()
	if err != nil {
		t.Fatalf("%v", err)
	} else if len(jails) == 0 {
		t.Fatalf("expected at least one jail")
	}
}

func TestDying(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	jails, err := jail.Dying()
	if err != nil {
		t.Fatalf("%v", err)
	} else if len(jails) > 0 {
		t.Fatalf("expected zero jails")
	}
}

func TestFindByID(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	jj, err := jail.FindByID(j.ID)
	if err != nil {
		t.Fatalf("%v", err)
	} else if j.ID != jj.ID {
		t.Fatalf("expected to find the same jail")
	}
}

func TestGetBool(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	dying, err := j.GetBool("dying")
	if err != nil {
		t.Fatalf("%v", err)
	} else if dying {
		t.Fatalf("expected jail to be alive")
	}
}

func TestGetString(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	path, err := j.GetString("path")
	if err != nil {
		t.Fatalf("%v", err)
	} else if path != "/tmp/jail" {
		t.Fatalf("expected path to be /tmp/jail but was %s", path)
	}
}

func TestGetInt32(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	_, err := j.GetInt32("children.max")
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestSetSecureLevel(t *testing.T) {
	j := newJail(t)
	defer jail.Remove(j.ID)
	err := j.SetSecureLevel(3)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func init() {
	log.SetFlags(0)
	u, err := user.Current()
	if err != nil || u.Uid != "0" {
		log.Fatalf("you must be root to run these tests")
	}
	stat, err := os.Stat("/tmp/jail")
	if err != nil || !stat.IsDir() {
		log.Fatalf("A base install of FreeBSD is expected in /tmp/jail")
	}
}
