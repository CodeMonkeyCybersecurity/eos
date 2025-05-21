//pkg/parse/csv.go

package parse

import "strings"

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
