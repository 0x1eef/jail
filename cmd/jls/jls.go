package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"git.hardenedbsd.org/0x1eef/jail"
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
	jails = filterByJID(jails, jid)
	if len(flag.Args()) > 0 {
		printJailParams(jails)
	} else {
		printJailTable(jails)
	}
	if jid == -1 && len(jails) == 0 {
		printf("jls: no jails found")
	} else if len(jails) == 0 {
		fatalf("jls: jail %d not found", jid)
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
	printf("Usage: jls [options] [parameter ...] \n")
	flag.PrintDefaults()
	os.Exit(1)
}

// Prints param values
func printJailParams(jails []*jail.Jail) {
	for _, param := range flag.Args() {
		for _, j := range jails {
			p, err := j.GetAny(param)
			if err != nil {
				fatalf("jls: %s", err)
			}
			if s, ok := p.(string); ok {
				printf("%s ", s)
			} else if t, ok := p.(bool); ok {
				printf("%t ", t)
			} else if d, ok := p.(int32); ok {
				printf("%d ", d)
			}
			printf("\n")
		}
	}
}

// Prints a table of jails
func printJailTable(jails []*jail.Jail) {
	printf(header, "JID", "IP Address", "Hostname", "Path")
	for _, j := range jails {
		printf(row, j.ID, "", j.Hostname, j.Path)
	}
}

func filterByJID(jails []*jail.Jail, jid int) []*jail.Jail {
	if jid == -1 {
		return jails
	}
	filtered := make([]*jail.Jail, 0, 1)
	for _, j := range jails {
		if j.ID == int32(jid) {
			filtered = append(filtered, j)
		}
	}
	return filtered
}

func init() {
	log.SetFlags(0)
	flag.IntVar(&jid, "j", -1, "The jid of the jail to list")
	flag.BoolVar(&check, "c", false, "Only check for the jail's existence")
	flag.BoolVar(&dying, "d", false, "List dying as well as active jails")
	flag.BoolVar(&help, "h", false, "Show help")
	flag.Parse()
}
