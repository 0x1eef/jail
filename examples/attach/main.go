package main

import "git.hardenedbsd.org/0x1eef/jail"

func main() {
	j, err := jail.FindByID(1)
	if err != nil {
		panic(err)
	}
	if err := j.Attach(); err != nil {
		panic(err)
	}
	// do something in the jail
}
