/* pkg/interaction/resolver.go */

package interaction

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func Resolve(prompt string) (bool, error) {
	fmt.Printf("%s (y/N): ", prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes", nil
}

func ResolveObject(c Confirmable) (bool, error) {
	fmt.Println(c.Summary())
	return Resolve("Are these values correct?")
}
