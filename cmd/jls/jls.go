package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/briandowns/jail"
)

const (
	header = "%6s  %-15s  %-30s  %s\n"
	row    = "%6d  %-15s  %-30s  %s\n"
)

var (
	jid   int
	check bool
	dying bool
)

func main() {
	if check && jid == -1 {
		fatalf("jls: -j jail to check must be provided for -c")
	}
	var (
		jails []*jail.Jail
		err   error
	)
	if dying {
		jails, err = jail.All()
	} else {
		jails, err = jail.Living()
	}
	if err != nil {
		fatalf("jls: %s", err)
	}
	printf(header, "JID", "IP Address", "Hostname", "Path")
	match := false
	for _, j := range jails {
		if jid == -1 {
			match = true
			printf(row, j.ID, "", j.Hostname, j.Path)
		} else {
			if int32(jid) == j.ID {
				match = true
				printf(row, j.ID, "", j.Hostname, j.Path)
			}
		}
	}
	if !match {
		fatalf("jls: jail \"%d\" not found", jid)
		os.Exit(1)
	}
}

func printf(str string, fmts ...any) {
	if !check {
		fmt.Printf(str, fmts...)
	}
}

func fatalf(str string, fmts ...any) {
	if !check {
		log.Fatalf(str, fmts...)
	}
}

func init() {
	log.SetFlags(0)
	flag.IntVar(&jid, "j", -1, "jail")
	flag.BoolVar(&check, "c", false, "check")
	flag.BoolVar(&dying, "d", false, "dying")
	flag.Parse()
}
