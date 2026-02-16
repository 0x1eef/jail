<p align="center">
  <a href="jail"><img src="https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEi39c9ab6rTHulzqrvy45M_omMN8cUyRxfaAph0UhlpubhMxgnJVyOEarYGmHNZgt1uUZmO8cobmrloSiAfxUjgjNOVvRZrF9n9b5tO0S-sG7e9DHfalqyYQZm6aY1jV55IzPbGPA/s1600/freebsd_jail.png" width="200" height="200" border="0" alt="jail"></a>
</p>
<p align="center">
  <a href="https://pkg.go.dev/git.hardenedbsd.org/0x1eef/jail"><img src="https://pkg.go.dev/badge/git.hardenedbsd.org/0x1eef/jail.svg" alt="Go Reference"></a>
  <a href="https://opensource.org/license/0bsd"><img src="https://img.shields.io/badge/License-0BSD-orange.svg?" alt="License"></a>
  <a href="https://github.com/0x1eef/jail/tags"><img src="https://img.shields.io/badge/version-0.1.1-green.svg?" alt="Version"></a>
</p>

## About

This repository provides a Go library that can manage FreeBSD jails
through low-level system calls that are exposed through a high-level
Go interface. The library originally forked from
[briandowns/jail](https://github.com/briandowns/jail)
and has diverged significantly since then.

## Examples

**jail.NewJail**

This function creates a new jail. It requires only a path and returns
an instance of **jail.Jail**. The path should have a base install of
FreeBSD. Everything else can be configured once the jail has been created,
and through the instance of **jail.Jail** that has been returned to the
caller:

```go
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
	if err := j.SetSecureLevel(3); err != nil {
		return err
	}
	// etc...
	return nil
}
```

**jail.Living**

This function returns a `[]*jail.Jail` slice that represents active
jails on a system. The opposite of this function is **jail.Dying**, and
it returns all jails in the process of dying. The **jail.All** returns
jails that are living and dying. See [jail_query.go](jail_query.go)
for more information on these functions:

```go
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
```

**jail.FindByID**

FindByID is a function that finds a jail by its ID. Afterwards, the jail can be
modified in a number of different ways. See [jail_types.go](jail_types.go) for
the list of runtime toggles. Our example will strip root of its superuser privileges
in a jail through the `DenyRoot` method:

```go
package main

import "git.hardenedbsd.org/0x1eef/jail"

func main() {
	j, err := jail.FindByID(1)
	if err != nil {
		panic(err)
	}
	if err := j.DenyRoot(); err != nil {
		panic(err)
	}
}
```

**jail.Attach**

The Attach function can be used to attach the current
process to a jail. The function changes the process's
root and current directories to the jail's path directory.
For convenience, the Attach function is provided as a
package-level function and as a method on the **jail.Jail**
struct:

```go
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
```

**jail.Remove**

The Remove function can be used to remove a jail from the system.
Removing a jail is destructive and requires sufficient privileges.
The function will kill all processes belonging to the jail, and
remove any children of that jail. For convenience, the Remove
function is provided as a package-level function and as a method
on the **jail.Jail** struct:

```go
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
```

**Jail.Get{Bool,String,Int32,Any}**

The [Jail struct](jail_types.go) exposes core fields and makes a best effort
to expose additional parameters beyond that, but it cannot cover everything
on every system. For anything not covered by the struct, then there's **GetBool**,
**GetString**, **GetInt32**, and **GetAny** to query a parameter directly
by name:

```go
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
```

**Jail.GetAny**

The **GetAny** function is a more flexible version of the other Get functions.
It returns an `any` type that can be type asserted to the correct type by
the caller. This is useful in case the caller is unsure of the type of a
parameter, for example when given a parameter name as an arbitrary string.

Please note though that FreeBSD stores booleans as integers. So `GetAny` uses
best-effort type detection: it first checks for string values, then checks
known boolean parameters (`allow.*`, `vnet`, `dying`, `persist`), then falls
back to `int32`. It's not perfect, but works most the time, and in the worst
case a boolean may be returned as an `int32` with a value of 0 or 1:

```go
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
```

## Credits

* [@bdowns328](http://twitter.com/bdowns328) (original author)
* www.debarbora.com (image)

## Sources

* [github.com/@0x1eef](https://github.com/0x1eef/jail)
* [codeberg.org/@0x1eef](https://codeberg.org/0x1eef/jail)
* [bsd.cafe/@0x1eef](https://brew.bsd.cafe/0x1eef/jail)
* [hardenedbsd.org/@0x1eef](https://git.HardenedBSD.org/0x1eef/jail)

## License

Original code is [BSD 2 Clause](https://choosealicense.com/licenses/bsd-2-clause/) <br>
See [LICENSE](./LICENSE) <br>

Modifications and new files in this fork are [BSD 0 Clause](https://choosealicense.com/licenses/0bsd/) <br>
See [0LICENSE](./0LICENSE)
