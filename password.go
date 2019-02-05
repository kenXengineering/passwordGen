package passwordGen

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

const (
	// LowerLetters is the list of lowercase letters.
	LowerLetters = "abcdefghijklmnopqrstuvwxyz"

	// UpperLetters is the list of uppercase letters.
	UpperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// Digits is the list of permitted digits.
	Digits = "0123456789"

	// Symbols is the list of symbols.
	Symbols = "~!@#$%^&*()_+-={}[]"
)

var (
	ErrExceedsTotalLength    = errors.New("the number of required elements exceeds requested password length")
	ErrNoCharactersSpecified = errors.New("no characters specified in generator")
)

// Generator is the stateful generator which can be used to customize the list
// of letters, digits, and/or symbols.
type generator struct {
	withLower   bool
	withUpper   bool
	withDigits  bool
	withSymbols bool

	requireLower   int
	requireUpper   int
	requireDigits  int
	requireSymbols int
}

// Generator Returns a new empty generator
func Generator() *generator {
	return &generator{}
}

// WithLower adds lower case letters to the password pool.
// Does not guarantee lower case letters will be present in the generated password.
func (g *generator) WithLower() *generator {
	g.withLower = true
	return g
}

// WithUpper adds upper case letters to the password pool.
// Does not guarantee upper case letters will be present in the generated password.
func (g *generator) WithUpper() *generator {
	g.withUpper = true
	return g
}

// WithDigits add digits to the password pool
// Does not guarantee digits will be present in the generated password.
func (g *generator) WithDigits() *generator {
	g.withDigits = true
	return g
}

// WithSymbols adds symbols to the password bool.
// Does not guarantee symbols will be present in the generated password.
func (g *generator) WithSymbols() *generator {
	g.withSymbols = true
	return g
}

// RequireLower guarantee that at least N number of lower case letters will be in the generated password.
func (g *generator) RequireLower(N int) *generator {
	g.withLower = true
	g.requireLower = N
	return g
}

// RequireUpper guarantee that at least N number of upper case letters will be in the generated password.
func (g *generator) RequireUpper(N int) *generator {
	g.withUpper = true
	g.requireUpper = N
	return g
}

// RequireDigits guarantee that at least N number of digits will be in the generated password.
func (g *generator) RequireDigits(N int) *generator {
	g.withDigits = true
	g.requireDigits = N
	return g
}

// RequireSymbols guarantee that at least N number of symbols will be in the generated password.
func (g *generator) RequireSymbols(N int) *generator {
	g.withSymbols = true
	g.requireSymbols = N
	return g
}

/* Generate will generate a password at the specified length as configured.
	Example:
	Genrator().WithLower().WithUpper().WithDigits().WithSymbols().Generate() will generate a password that may contain
 lower character letters, upper character letters, digits, and symbols.

	Generator.WithLower().WithUpper().RequireDigits(1).WithSymbols().Generate() will generate a password that may contain
 lower characters, upper charcters, at least 1 digits, and may contain symbols.
*/
func (g *generator) Generate(length int) (string, error) {
	if !g.withLower && !g.withUpper && !g.withDigits && !g.withSymbols {
		return "", ErrNoCharactersSpecified
	}

	buffer := strings.Builder{}

	if g.requireLower+g.requireUpper+g.requireDigits+g.requireSymbols > length {
		return "", ErrExceedsTotalLength
	}

	if g.requireLower > 0 {
		for i := 0; i < g.requireLower; i++ {
			elm, err := randomElement(LowerLetters)
			if err != nil {
				return "", err
			}
			buffer.WriteString(elm)
		}
	}

	if g.requireUpper > 0 {
		for i := 0; i < g.requireUpper; i++ {
			elm, err := randomElement(UpperLetters)
			if err != nil {
				return "", err
			}
			buffer.WriteString(elm)
		}
	}

	if g.requireDigits > 0 {
		for i := 0; i < g.requireDigits; i++ {
			elm, err := randomElement(Digits)
			if err != nil {
				return "", err
			}
			buffer.WriteString(elm)
		}
	}

	if g.requireSymbols > 0 {
		for i := 0; i < g.requireSymbols; i++ {
			elm, err := randomElement(Symbols)
			if err != nil {
				return "", err
			}
			buffer.WriteString(elm)
		}
	}

	bufferLen := buffer.Len()
	if buffer.Len() < length {
		// Need to continue building the password pool
		valuesBuilder := strings.Builder{}
		if g.withLower {
			valuesBuilder.WriteString(LowerLetters)
		}
		if g.withUpper {
			valuesBuilder.WriteString(UpperLetters)
		}
		if g.withDigits {
			valuesBuilder.WriteString(Digits)
		}
		if g.withSymbols {
			valuesBuilder.WriteString(Symbols)
		}
		values := valuesBuilder.String()
		// Fill the password pool up to the defined length
		for i := 0; i < length-bufferLen; i++ {
			elm, err := randomElement(values)
			if err != nil {
				return "", err
			}
			buffer.WriteString(elm)
		}
	}

	// We now have a buffer with the passwords elements in it, shuffle it
	// Shuffle with shuffle the password in slice, so we have to cast it to a rune slice
	// then back to a string.
	pass := buffer.String()
	runePass := []rune(pass)
	shuffle(runePass)
	pass = string(runePass)

	return pass, nil
}

// shuffle shuffles the values in a run slice in place
func shuffle(vals []rune) {
	for len(vals) > 0 {
		n := len(vals)
		randIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		vals[n-1], vals[randIndex.Int64()] = vals[randIndex.Int64()], vals[n-1]
		vals = vals[:n-1]
	}
}

// randomElement extracts a random element from the given string.
func randomElement(s string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s))))
	if err != nil {
		return "", err
	}
	return string(s[n.Int64()]), nil
}
