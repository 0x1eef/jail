<p align="center">
  <a href="jail"><img src="https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEi39c9ab6rTHulzqrvy45M_omMN8cUyRxfaAph0UhlpubhMxgnJVyOEarYGmHNZgt1uUZmO8cobmrloSiAfxUjgjNOVvRZrF9n9b5tO0S-sG7e9DHfalqyYQZm6aY1jV55IzPbGPA/s1600/freebsd_jail.png" width="200" height="200" border="0" alt="jail"></a>
</p>
<p align="center">
  <a href="https://godoc.org/github.com/briandowns/jail"><img src="https://godoc.org/github.com/briandowns/jail?status.svg" alt="GoDoc"></a>
  <a href="https://opensource.org/licenses/BSD-3-Clause"><img src="https://img.shields.io/badge/License-BSD%203--Clause-orange.svg?" alt="License"></a>
  <a href="https://github.com/briandowns/jail/releases"><img src="https://img.shields.io/badge/version-0.1.0-green.svg?" alt="Version"></a>
</p>

## About

This repository provides a Go library that can manage FreeBSD jails
through low-level system calls that are exposed through a high-level
Go interface. The library originally forked from
[briandowns/jail](https://github.com/briandowns/jail)
and has diverged significantly since then.

## Examples

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

## Credits

* [@bdowns328](http://twitter.com/bdowns328) (original author)
* www.debarbora.com (image)

## Sources

* [github.com/@0x1eef](https://github.com/0x1eef/jail)
* [hardenedbsd.org/@0x1eef](https://git.HardenedBSD.org/0x1eef/jail)

## License

[BSD 2 Clause](https://choosealicense.com/licenses/bsd-2-clause/) <br>
See [LICENSE](./LICENSE)
