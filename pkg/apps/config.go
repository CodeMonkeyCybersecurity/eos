// pkg/apps/config.go

package apps

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consts"
)

//
// ---------------------------- APP DEFINITIONS ---------------------------- //
//

type App struct {
	Option   string
	Name     string
	ConfFile string
	Markers  []string
}

var Apps = []App{
	{"1", "Static website", "base.conf", consts.DefaultMarkers},
	{"2", "Wazuh", "delphi.conf", consts.CombineMarkers("1515", "1514", "55000")},
	{"3", "Mattermost", "collaborate.conf", consts.DefaultMarkers},
	{"4", "Nextcloud", "cloud.conf", consts.CombineMarkers("3478", "coturn:")},
	{"5", "Mailcow", "mailcow.conf", consts.CombineMarkers("25", "587", "465", "110", "995", "143", "993")},
	{"6", "Jenkins", "jenkins.conf", consts.DefaultMarkers},
	{"7", "Grafana", "observe.conf", consts.DefaultMarkers},
	{"8", "Umami", "analytics.conf", consts.DefaultMarkers},
	{"9", "MinIO", "s3.conf", consts.DefaultMarkers},
	{"10", "Wiki.js", "wiki.conf", consts.DefaultMarkers},
	{"11", "ERPNext", "erp.conf", consts.DefaultMarkers},
	{"12", "Jellyfin", "jellyfin.conf", consts.DefaultMarkers},
	{"13", "Persephone", "persephone.conf", consts.DefaultMarkers},
}

func GetSupportedAppNames() []string {
	var names []string
	for _, app := range Apps {
		names = append(names, strings.ToLower(app.Name))
	}
	return names
}

func DisplayOptions() {
	fmt.Println("Available Hecate backend web apps:")
	var sortedApps []int
	for _, app := range Apps {
		if num, err := strconv.Atoi(app.Option); err == nil {
			sortedApps = append(sortedApps, num)
		}
	}
	sort.Ints(sortedApps)
	for _, num := range sortedApps {
		for _, app := range Apps {
			if app.Option == strconv.Itoa(num) {
				fmt.Printf("  %s. %s -> %s\n", app.Option, app.Name, app.ConfFile)
				break
			}
		}
	}
}

func GetAppByOption(option string) (App, bool) {
	for _, app := range Apps {
		if app.Option == option {
			return app, true
		}
	}
	return App{}, false
}

func GetUserSelection(defaultSelection string) (map[string]App, string) {
	reader := bufio.NewReader(os.Stdin)
	promptMsg := "Enter the numbers (comma-separated) of the apps you want enabled (or type 'all' for all supported)"
	if defaultSelection != "" {
		promptMsg += fmt.Sprintf(" [default: %s]", defaultSelection)
	}
	promptMsg += ": "

	fmt.Print(promptMsg)
	selection, _ := reader.ReadString('\n')
	selection = strings.TrimSpace(selection)
	if selection == "" && defaultSelection != "" {
		selection = defaultSelection
	}

	selectedApps := make(map[string]App)
	if strings.ToLower(selection) == "all" {
		for _, app := range Apps {
			selectedApps[strings.ToLower(app.Name)] = app
		}
		return selectedApps, "all"
	}

	parts := strings.Split(selection, ",")
	for _, token := range parts {
		token = strings.TrimSpace(token)
		app, ok := GetAppByOption(token)
		if !ok {

			fmt.Printf("Invalid option: %s\n", token)
			return GetUserSelection(defaultSelection)
		}
		selectedApps[strings.ToLower(app.Name)] = app
	}
	if len(selectedApps) == 0 {
		fmt.Println("No valid options selected.")
		return GetUserSelection(defaultSelection)
	}
	return selectedApps, selection
}
