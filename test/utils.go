package test

import (
	"testing"

	"git.hardenedbsd.org/0x1eef/jail"
)

func newJail(t *testing.T) *jail.Jail {
	j, err := jail.NewJail("/tmp/jail")
	if err != nil {
		t.Fatalf("new jail fail: %v", err)
	}
	return j
}
