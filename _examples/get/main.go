package main

import (
	//"fmt"
	"encoding/json"
	"github.com/briandowns/jail"
)

func main() {
	j, _ := jail.FindByID(4)
	b, _ := json.Marshal(j)
	println(string(b))
}
