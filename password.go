package passwordgen

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

	// LowerLettersNoAmbig is the list of lowercase letters.
	LowerLettersNoAmbig = "abcdefghjkmnpqrstuvwxyz"

	// UpperLettersNoAmbig is the list of uppercase letters.
	UpperLettersNoAmbig = "ABCDEFGHJKMNPQRSTUVWXYZ"

	// DigitsNoAmbig is the list of permitted digits.
	DigitsNoAmbig = "23456789"

	// SymbolsNoAmbig is the list of symbols.
	SymbolsNoAmbig = "~!@#$%^&*()_+-={}[]"
)

var (
	// ErrExceedsTotalLength is the error returned when the number of required
	// elements is greater then the length of the requestd password
	ErrExceedsTotalLength = errors.New("the number of required elements exceeds requested password length")

	// ErrNoCharactersSpecified is the error returned when a generator is called
	// without any characters specified
	ErrNoCharactersSpecified = errors.New("no characters specified in generator")
)

// Generator is the stateful generator which can be used to customize the list
// of letters, digits, and/or symbols.
type Generator struct {
	lowerLetters string
	upperLetters string
	digits       string
	symbols      string

	withLower   bool
	withUpper   bool
	withDigits  bool
	withSymbols bool

	requireLower   int
	requireUpper   int
	requireDigits  int
	requireSymbols int
}

// NewGenerator Returns a new empty generator.
func NewGenerator() *Generator {
	return &Generator{
		lowerLetters: LowerLetters,
		upperLetters: UpperLetters,
		digits:       Digits,
		symbols:      Symbols,
	}
}

// NoAmbiguousCharacters ensures no ambiguous characters will be in the password.
func (g *Generator) NoAmbiguousCharacters() *Generator {
	g.lowerLetters = LowerLettersNoAmbig
	g.upperLetters = UpperLettersNoAmbig
	g.digits = DigitsNoAmbig
	g.symbols = SymbolsNoAmbig
	return g
}

// WithLower adds lower case letters to the password pool.
// Does not guarantee lower case letters will be present in the generated password.
func (g *Generator) WithLower() *Generator {
	g.withLower = true
	return g
}

// WithUpper adds upper case letters to the password pool.
// Does not guarantee upper case letters will be present in the generated password.
func (g *Generator) WithUpper() *Generator {
	g.withUpper = true
	return g
}

// WithDigits adds digits to the password pool.
// Does not guarantee digits will be present in the generated password.
func (g *Generator) WithDigits() *Generator {
	g.withDigits = true
	return g
}

// WithSymbols adds symbols to the password pool.
// Does not guarantee symbols will be present in the generated password.
func (g *Generator) WithSymbols() *Generator {
	g.withSymbols = true
	return g
}

// RequireLower guarantees that at least N number of lower case letters will be in the generated password.
func (g *Generator) RequireLower(N int) *Generator {
	g.withLower = true
	g.requireLower = N
	return g
}

// RequireUpper guarantees that at least N number of upper case letters will be in the generated password.
func (g *Generator) RequireUpper(N int) *Generator {
	g.withUpper = true
	g.requireUpper = N
	return g
}

// RequireDigits guarantees that at least N number of digits will be in the generated password.
func (g *Generator) RequireDigits(N int) *Generator {
	g.withDigits = true
	g.requireDigits = N
	return g
}

// RequireSymbols guarantees that at least N number of symbols will be in the generated password.
func (g *Generator) RequireSymbols(N int) *Generator {
	g.withSymbols = true
	g.requireSymbols = N
	return g
}

// ExactLower guarantees that there are exactly N lower case letters in the generated password.
func (g *Generator) ExactLower(N int) *Generator {
	g.withLower = false
	g.requireLower = N
	return g
}

// ExactUpper guarantees that there are exactly N update case letters in the generated password.
func (g *Generator) ExactUpper(N int) *Generator {
	g.withUpper = false
	g.requireUpper = N
	return g
}

// ExactDigits guarantees that there are exactly N digits in the generated password.
func (g *Generator) ExactDigits(N int) *Generator {
	g.withDigits = false
	g.requireDigits = N
	return g
}

// ExactSymbols guarantees that there are exactly N symbols in the generated password.
func (g *Generator) ExactSymbols(N int) *Generator {
	g.withSymbols = false
	g.requireSymbols = N
	return g
}

// Generate will generate a password at the specified length as configured.
func (g *Generator) Generate(length int) (string, error) {
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
	if bufferLen < length {
		// Need to continue building the password pool
		valuesBuilder := strings.Builder{}
		if g.withLower {
			valuesBuilder.WriteString(g.lowerLetters)
		}
		if g.withUpper {
			valuesBuilder.WriteString(g.upperLetters)
		}
		if g.withDigits {
			valuesBuilder.WriteString(g.digits)
		}
		if g.withSymbols {
			valuesBuilder.WriteString(g.symbols)
		}
		// The only reason this could be zero is Exact<type> was used and we don't have enough
		// characters in the password buffer.  Error out as an invalid password generator
		// was created.
		if valuesBuilder.Len() == 0 {
			return "", ErrNoCharactersSpecified
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
