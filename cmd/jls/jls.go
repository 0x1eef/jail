package main

import (
	"fmt"
	"log"

	"github.com/briandowns/jail"
)

func main() {
	jails, err := jail.All()
	if err != nil {
		log.Fatalf("jls: %s", err)
	}
	fmt.Printf("%6s  %-15s  %-30s  %s\n", "JID", "IP Address", "Hostname", "Path")
	for _, j := range jails {
		fmt.Printf("%6d  %-15s  %-30s  %s\n", j.ID, "", j.Hostname, j.Path)
	}
}
