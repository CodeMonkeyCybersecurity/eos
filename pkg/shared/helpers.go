// pkg/shared/vars.go

package shared

func CombineMarkers(additional ...string) []string {
	return append(DefaultMarkers, additional...)
}
