package main

import (
	"fmt"
	"os"

	"git.hardenedbsd.org/0x1eef/jail"
)

func main() {
	j, err := jail.FindByID(1)
	if err != nil {
		panic(err)
	}
	p, err := j.GetAny(os.Args[1])
	if err != nil {
		panic(err)
	}
	if s, ok := p.(string); ok {
		fmt.Printf("%s ", s)
	} else if b, ok := p.(bool); ok {
		fmt.Printf("%t ", b)
	} else if i, ok := p.(int32); ok {
		fmt.Printf("%d ", i)
	} else {
		// ????
	}
}
