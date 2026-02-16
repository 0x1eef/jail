package main

import (
	"errors"
	"fmt"

	"git.hardenedbsd.org/0x1eef/jail"
	"golang.org/x/sys/unix"
)

func main() {
	j, err := jail.FindByID(1)
	if err != nil {
		panic(err)
	}
	rules, err := j.GetString("security.mac.do.rules")
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
		fmt.Println("parameter unsupported")
	} else if err != nil {
		panic(err)
	} else {
		fmt.Printf("rules: %s\n", rules)
	}
}
