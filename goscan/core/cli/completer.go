package cli

import (
	"fmt"
	"github.com/c-bata/go-prompt"
	"goscan/core/utils"
	"io/ioutil"
	"path/filepath"
	"strings"
)

func excludeOptions(args []string) []string {
	ret := make([]string, 0, len(args))
	for i := range args {
		if !strings.HasPrefix(args[i], "-") {
			ret = append(ret, args[i])
		}
	}
	return ret
}

func Completer(d prompt.Document) []prompt.Suggest {
	if d.TextBeforeCursor() == "" {
		return []prompt.Suggest{}
	}
	args := strings.Split(d.TextBeforeCursor(), " ")

	// If PIPE is in text before the cursor, returns empty suggestions.
	for i := range args {
		if args[i] == "|" {
			return []prompt.Suggest{}
		}
	}
	return argumentsCompleter(d, excludeOptions(args))
}

var commands = []prompt.Suggest{
	{Text: "set_target", Description: "Set target CIDR."},
	{Text: "set_output_folder", Description: "Set the output folder."},
	{Text: "show", Description: "Show results."},
	{Text: "sweep", Description: "Perform an ARP/ping sweep."},
	{Text: "portscan", Description: "Perform a port scan."},
	{Text: "enumerate", Description: "Perform enumeration of detected services."},
	{Text: "help", Description: "Show help"},
	{Text: "exit", Description: "Exit this program"},
}

func argumentsCompleter(d prompt.Document, args []string) []prompt.Suggest {
	if len(args) <= 1 {
		return prompt.FilterHasPrefix(commands, args[0], true)
	}

	first := args[0]
	switch first {
	case "set_target":
		if len(args) == 2 {
			return prompt.FilterContains(getTargetSuggestions(), args[1], true)
		}
	case "set_output_folder":
		return fileCompleter(d)
	case "show":
		second := args[1]
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "hosts", Description: "Show live hosts"},
			}
			return prompt.FilterHasPrefix(subcommands, second, true)
		}
	case "sweep":
		second := args[1]
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "ALL", Description: "Perform ARP scan and PING sweep"},
				{Text: "ARP", Description: "Perform ARP scan"},
				{Text: "PING", Description: "Perform PING sweep"},
			}
			return prompt.FilterHasPrefix(subcommands, second, true)
		}
		if len(args) == 3 {
			return prompt.FilterContains(getTargetSuggestions(), args[2], true)
		}
	case "portscan":
		second := args[1]
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "TCP-FULL", Description: "Perform FULL TCP scan"},
				{Text: "TCP-STANDARD", Description: "Perform TCP scan (top 200)"},
				{Text: "TCP-VULN-SCAN", Description: "Perform TCP VULN scan (vulscan.nse)"},
				{Text: "UDP-STANDARD", Description: "Perform UDP scan (common ports)"},
			}
			return prompt.FilterHasPrefix(subcommands, second, true)
		}
		if len(args) == 3 {
			return prompt.FilterContains(getHostSuggestions(), args[2], true)
		}
	case "enumerate":
		if len(args) == 2 {
			second := args[1]
			subcommands := []prompt.Suggest{
				{Text: "ALL", Description: "Automatically identify open services and enumerate them"},
				{Text: "DNS", Description: "Enumerate DNS"},
				{Text: "FINGER", Description: "Enumerate FINGER"},
				{Text: "FTP", Description: "Enumerate FTP"},
				{Text: "HTTP", Description: "Enumerate HTTP"},
				{Text: "RDP", Description: "Enumerate RDP"},
				{Text: "SMB", Description: "Enumerate SMB"},
				{Text: "SMTP", Description: "Enumerate SMTP"},
				{Text: "SNMP", Description: "Enumerate SNMP"},
				{Text: "SQL", Description: "Enumerate SQL"},
				{Text: "SSH", Description: "Enumerate SSH"},
			}
			return prompt.FilterHasPrefix(subcommands, second, true)
		}
		if len(args) == 3 {
			third := args[2]
			subcommands := []prompt.Suggest{
				{Text: "POLITE", Description: "Avoid bruteforcing"},
				{Text: "BRUTEFORCE", Description: "Include bruteforce scripts"},
			}
			return prompt.FilterHasPrefix(subcommands, third, true)
		}
		if len(args) == 4 {
			return prompt.FilterContains(getHostSuggestions(), args[3], true)
		}
	default:
		return []prompt.Suggest{}
	}

	return []prompt.Suggest{}
}

func getHostSuggestions() []prompt.Suggest {
	s := []prompt.Suggest{}
	s = append(s, prompt.Suggest{
		Text:        "ALL",
		Description: "Scan all live hosts",
	})

	for _, h := range utils.Config.Hosts {
		s = append(s, prompt.Suggest{
			Text:        h.Address,
			Description: fmt.Sprintf("Scan only host: %s", h.Address),
		})
	}

	return s
}

func getTargetSuggestions() []prompt.Suggest {
	// Default suggestions
	var target string = utils.Const_example_target_cidr
	var desc string = utils.Const_example_target_desc

	// Detect if a target has already been selected
	if utils.Config.Target != "" {
		target = fmt.Sprintf("%s", utils.Config.Target)
		desc = "Currently selected target"
	}

	// Build suggestion
	s := make([]prompt.Suggest, 1, 5)
	s[0] = prompt.Suggest{
		Text:        target,
		Description: desc,
	}

	// Parse address from network interface
	localInterfaces := utils.ParseLocalIP()
	for eth, ip := range localInterfaces {
		s = append(s, prompt.Suggest{
			Text:        utils.ParseCIDR(ip),
			Description: fmt.Sprintf("Subnet from interface: %s", eth),
		})

	}

	return s
}

func fileCompleter(d prompt.Document) []prompt.Suggest {
	path := d.GetWordBeforeCursor()
	if strings.HasPrefix(path, "./") {
		path = path[2:]
	}
	dir := filepath.Dir(path)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return []prompt.Suggest{}
	}
	suggests := make([]prompt.Suggest, 0, len(files))
	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		suggests = append(suggests, prompt.Suggest{Text: filepath.Join(dir, f.Name())})
	}
	return prompt.FilterHasPrefix(suggests, path, false)
}
