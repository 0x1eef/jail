package main

import (
	"fmt"

	"git.hardenedbsd.org/0x1eef/jail"
)

func main() {
	if jails, err := jail.Living(); err != nil {
		panic(err)
	} else {
		for _, j := range jails {
			fmt.Printf("%s: %s\n", "name", j.Name)
			fmt.Printf("%s: %s\n", "path", j.Path)
			fmt.Printf("%s: %s\n", "hostname", j.Hostname)
			fmt.Printf("\n")
		}
	}
}
