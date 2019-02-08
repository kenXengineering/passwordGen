package passwordgen

import (
	"log"
	"regexp"
	"testing"
)

var (
	containsLower    = regexp.MustCompile("([a-z])+")
	containsUpper    = regexp.MustCompile("([A-Z])+")
	containsDigits   = regexp.MustCompile("([0-9])+")
	containsSymnbols = regexp.MustCompile("([~!@#$%^&*()_+\\-={}[\\]])+")

	exactNumer = 5
)

func TestGenerator_Generate(t *testing.T) {
	t.Parallel()

	t.Run("exceeds_length", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().RequireDigits(5).RequireLower(5)
		if _, err := gen.Generate(5); err != ErrExceedsTotalLength {
			t.Errorf("expected: %q, actual: %q", err, ErrExceedsTotalLength)
		}
	})

	t.Run("no_characters", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator()
		if _, err := gen.Generate(5); err != ErrNoCharactersSpecified {
			t.Errorf("expected: %q, actual: %q", err, ErrNoCharactersSpecified)
		}
	})

	t.Run("require_lower", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().RequireLower(1).WithUpper().WithDigits().WithSymbols()
		pass, err := gen.Generate(10)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		if !containsLower.Match([]byte(pass)) {
			t.Errorf("password %s does not contain lower cap characters", pass)
		}
	})

	t.Run("require_upper", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().RequireUpper(1).WithLower().WithDigits().WithSymbols()
		pass, err := gen.Generate(10)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		if !containsUpper.Match([]byte(pass)) {
			t.Errorf("password %s does not contain upper cap characters", pass)
		}
	})

	t.Run("require_digits", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().RequireDigits(1).WithLower().WithUpper().WithSymbols()
		pass, err := gen.Generate(10)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		if !containsDigits.Match([]byte(pass)) {
			t.Errorf("password %s does not contain digit characters", pass)
		}
	})

	t.Run("require_symbol", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().RequireSymbols(1).WithLower().WithUpper().WithDigits()
		pass, err := gen.Generate(10)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		if !containsSymnbols.Match([]byte(pass)) {
			t.Errorf("password %s does not contain symbol characters", pass)
		}
	})

	t.Run("exact_lower", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().ExactLower(exactNumer).WithSymbols().WithUpper().WithDigits()
		pass, err := gen.Generate(10)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		matches := containsLower.FindAllString(pass, -1)
		count := 0
		for _, match := range matches {
			count += len(match)
		}
		if count != exactNumer {
			t.Errorf("Expected password %s to have exactly %d lower characters", pass, exactNumer)
		}
	})

	t.Run("exact_upper", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().ExactUpper(exactNumer).WithSymbols().WithLower().WithDigits()
		pass, err := gen.Generate(10)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		matches := containsUpper.FindAllString(pass, -1)
		count := 0
		for _, match := range matches {
			count += len(match)
		}
		if count != exactNumer {
			t.Errorf("Expected password %s to have exactly %d upper characters", pass, exactNumer)
		}
	})

	t.Run("exact_digit", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().ExactDigits(exactNumer).WithSymbols().WithLower().WithUpper()
		pass, err := gen.Generate(10)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		matches := containsDigits.FindAllString(pass, -1)
		count := 0
		for _, match := range matches {
			count += len(match)
		}
		if count != exactNumer {
			t.Errorf("Expected password %s to have exactly %d digit characters", pass, exactNumer)
		}
	})

	t.Run("exact_symbol", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().ExactSymbols(exactNumer).WithDigits().WithLower().WithUpper()
		pass, err := gen.Generate(10)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		matches := containsSymnbols.FindAllString(pass, -1)
		count := 0
		for _, match := range matches {
			count += len(match)
		}
		if count != exactNumer {
			t.Errorf("Expected password %s to have exactly %d symbol characters", pass, exactNumer)
		}
	})

	t.Run("correct_length", func(t *testing.T) {
		t.Parallel()
		gen := NewGenerator().RequireLower(3).RequireLower(3).RequireDigits(3).RequireSymbols(3)
		pass, err := gen.Generate(16)
		if err != nil {
			t.Errorf("expected no error, received %q", err)
		}
		if len(pass) != 16 {
			t.Errorf("Expected password %s to be 16 characters long", pass)
		}
	})
}

func ExampleGenerator_Generate() {
	pass, err := NewGenerator().WithUpper().WithLower().WithDigits().WithLower().Generate(8)
	if err != nil {
		log.Fatal(err)
	}
	log.Print(pass)
}

func ExampleGenerator_RequireUpper() {
	pass, err := NewGenerator().RequireUpper(3).WithLower().WithDigits().WithSymbols().Generate(8)

	if err != nil {
		log.Fatal(err)
	}

	log.Print(pass)
}

func ExampleGenerator_ExactUpper() {
	pass, err := NewGenerator().ExactUpper(3).WithLower().Generate(8)
	if err != nil {
		log.Fatal(err)
	}
	log.Print(pass)
}

func ExampleGenerator_NoAmbiguousCharacters() {
	pass, err := NewGenerator().NoAmbiguousCharacters().WithUpper().WithLower().WithDigits().WithSymbols().Generate(16)
	if err != nil {
		log.Fatal(err)
	}
	log.Print(pass)
}
