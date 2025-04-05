// pkg/interaction/prompt.go
package interaction

import (
	"fmt"
)

func PromptSelect(question string, options []string) string {
	fmt.Println(question)
	for i, opt := range options {
		fmt.Printf("  %d) %s\n", i+1, opt)
	}

	var choice int
	for {
		fmt.Print("> ")
		_, err := fmt.Scanf("%d\n", &choice)
		if err != nil || choice < 1 || choice > len(options) {
			fmt.Println("Invalid selection. Try again.")
			continue
		}
		break
	}
	return options[choice-1]
}
