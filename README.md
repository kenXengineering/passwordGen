## Golang Password Generator

[![GoDoc](https://godoc.org/github.com/kenXengineering/passwordgen?status.svg)](https://godoc.org/github.com/kenXengineering/passwordgen)

This library provides a password generated backed by crypto/rand that allows for deep custimization of generated password.
`passwordgen` allows you to specify which character groups are in the password gen pool.  You can also specify a mininum number of characters from a group that must be in the password, or even specify the exact number of characters from a group.

## Installation
```sh
$ go get -u github.com/kenXengineering/passwordgen
```

## Usage

Generate a password with lower, upper case characters, digits, and symbols.

```golang
package main

import (
    "log"
    "github.com/kenXengineering/passwordgen"
)

func main() {
    pass, err := passwordgen.NewGenerator().WithLower().WithUpper().WithDigits().WithSymbols().Generate(16)
    if err != nil {
        log.Fatal(err)
    }
    log.Print(pass)
}
```

Generate a password with at least 1 lower case character, 1 upper case character, 2 digits, and no symbols.

```golang
package main

import (
    "log"
    "github.com/kenXengineering/passwordgen"
)

func main() {
    pass, err := passwordgen.NewGenerator().RequireLower(1).RequireUpper(1).RequireDigits(2).Generate(8)
    if err != nil {
        log.Fatal(err)
    }
    log.Print(pass)
}
```

Generate a password with lower case, upper case characters, at least 2 digits, and exactly 2 symbols.

```golang
package main

import (
    "log"
    "github.com/kenXengineering/passwordgen"
)

func main() {
    pass, err := passwordgen.NewGenerator().WithLower().WithUpper().RequireDigits(2).ExactSymbol(2).Generate(8)
    if err != nil {
        log.Fatal(err)
    }
    log.Print(pass)
}
```

Create a generator that can be used later on.

```golang
package main

import (
    "log"
    "github.com/kenXengineering/passwordgen"
)

func main() {
    generator := passwordgen.NewGenerator().WithLower().WithUpper().WithDigits().WithSymbols()

    // .............

    pass, err := generator.Generate(16)
    if err != nil {
        log.Fatal(err)
    }
    log.Print(pass)
}
```


See the [GoDoc](https://godoc.org/github.com/kenXengineering/passwordgen) for more
information.

## License

This code is licensed under the MIT license.