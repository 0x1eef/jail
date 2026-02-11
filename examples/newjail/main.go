package main

import "git.hardenedbsd.org/0x1eef/jail"

func main() {
	j, err := jail.NewJail("/tmp/jail")
	if err != nil {
		panic(err)
	}
	if err := setup(j); err != nil {
		panic(err)
	}
}

func setup(j *jail.Jail) error {
	if err := j.SetName("tmp"); err != nil {
		return err
	}
	if err := j.SetHostname("tmp.local"); err != nil {
		return err
	}
	// etc...
	return nil
}
