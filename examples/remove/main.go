package main

import "git.hardenedbsd.org/0x1eef/jail"

func main() {
	j, err := jail.FindByID(1)
	if err != nil {
		panic(err)
	}
	if err := j.Remove(); err != nil {
		panic(err)
	}
}
