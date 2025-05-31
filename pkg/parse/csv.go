//pkg/parse/csv.go

package parse

import (
	"bufio"
	"encoding/csv"
	"errors"
	"io"
	"strings"
	"unicode"
)

func SplitAndTrim(input string) []string {
	var result []string
	tokens := strings.Split(input, ",")
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token != "" {
			result = append(result, token)
		}
	}
	return result
}

func ParseCSVLine(line string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(line))
	r.TrimLeadingSpace = true
	return r.Read()
}

func ParseSimpleINI(r io.Reader) (map[string]string, error) {
	res := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // skip malformed
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		res[key] = val
	}
	return res, sc.Err()
}

func ParseShellArgs(line string) ([]string, error) {
	var (
		args           []string
		arg            strings.Builder
		inQ, inSQ, esc bool
	)
	for _, r := range line {
		switch {
		case esc:
			arg.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == '"' && !inSQ:
			inQ = !inQ
		case r == '\'' && !inQ:
			inSQ = !inSQ
		case unicode.IsSpace(r) && !inQ && !inSQ:
			if arg.Len() > 0 {
				args = append(args, arg.String())
				arg.Reset()
			}
		default:
			arg.WriteRune(r)
		}
	}
	if arg.Len() > 0 {
		args = append(args, arg.String())
	}
	if inQ || inSQ {
		return nil, ErrUnclosedQuote
	}
	return args, nil
}

var ErrUnclosedQuote = errors.New("unclosed quote in input")
