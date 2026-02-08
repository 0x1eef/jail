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
	help  bool
)

func main() {
	var (
		jails []*jail.Jail
		err   error
	)
	if help {
		usage()
	}
	if check && jid == -1 {
		fatalf("jls: -j jail to check must be provided for -c")
	}
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

func printf(str string, args ...any) {
	if !check {
		fmt.Printf(str, args...)
	}
}

func fatalf(str string, args ...any) {
	if !check {
		log.Fatalf(str, args...)
	}
}

func usage() {
	printf("Usage: jls [options]\n")
	flag.PrintDefaults()
	os.Exit(1)
}

func init() {
	log.SetFlags(0)
	flag.IntVar(&jid, "j", -1, "The jid of the jail to list")
	flag.BoolVar(&check, "c", false, "Only check for the jail's existence")
	flag.BoolVar(&dying, "d", false, "List dying as well as active jails")
	flag.BoolVar(&help, "h", false, "Show help")
	flag.Parse()
}
