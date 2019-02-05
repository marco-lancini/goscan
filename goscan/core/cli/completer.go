package cli

import (
	"fmt"
	"github.com/c-bata/go-prompt"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/utils"
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

	{Text: "load", Description: "Import data at different stages of the process."},
	{Text: "sweep", Description: "Perform a Ping Sweep to discover alive hosts."},
	{Text: "portscan", Description: "Perform a port scan."},
	{Text: "enumerate", Description: "Perform enumeration of detected services."},
	{Text: "special", Description: "Special scans (EyeWitness, Domain Info, DNS)."},
	{Text: "show", Description: "Show results (hosts/ports/etc/)."},
	{Text: "set", Description: "Set different constants (output folder, nmap switches, wordlists)."},
	{Text: "help", Description: "Show help"},
	{Text: "exit", Description: "Exit this program"},
}

func argumentsCompleter(d prompt.Document, args []string) []prompt.Suggest {
	if len(args) <= 1 {
		return prompt.FilterHasPrefix(commands, args[0], true)
	}

	first := args[0]
	switch first {
	// -----------------------------------------------------------------------------------
	// UTILS
	// -----------------------------------------------------------------------------------
	case "show":
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "targets", Description: "Show targets."},
				{Text: "hosts", Description: "Show live hosts."},
				{Text: "ports", Description: "Show detailed ports information."},
			}
			return prompt.FilterHasPrefix(subcommands, args[1], true)
		}

	case "set":
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "config_file", Description: "Set configs from file."},
				{Text: "output_folder", Description: "Set the output folder."},
				{Text: "nmap_switches", Description: "Modify the default nmap switches."},
				{Text: "wordlists", Description: "Modify the default wordlists."},
			}
			return prompt.FilterHasPrefix(subcommands, args[1], true)
		}
		if len(args) == 3 {
			switch args[1] {
			case "config_file":
				return fileCompleter(d)
			case "output_folder":
				return fileCompleter(d)
			case "nmap_switches":
				subcommands := []prompt.Suggest{
					{Text: "SWEEP", Description: "Switches for ping sweep"},
					{Text: "TCP_FULL", Description: "Switches for TCP FULL scan"},
					{Text: "TCP_STANDARD", Description: "Switches for TCP STANDARD scan"},
					{Text: "TCP_VULN", Description: "Switches for TCP VULN scan"},
					{Text: "TCP_PROD", Description: "Switches for TCP PROD scan"},
					{Text: "UDP_STANDARD", Description: "Switches for UDP STANDARD scan"},
					{Text: "UDP_PROD", Description: "Switches for UDP PROD scan"},
				}
				return prompt.FilterHasPrefix(subcommands, args[2], true)
			case "wordlists":
				subcommands := []prompt.Suggest{
					{Text: "FINGER_USER", Description: "Wordlist for Finger user enumeration"},
					{Text: "FTP_USER", Description: "Wordlist for FTP user enumeration"},
					{Text: "SMTP", Description: "Wordlist for SMTP enumeration"},
					{Text: "SNMP", Description: "Wordlist for SNMP enumeration"},
					{Text: "DNS_BRUTEFORCE", Description: "Wordlist for DNS bruteforce"},
					{Text: "HYDRA_SSH_USER", Description: "Wordlist for SSH user bruteforce"},
					{Text: "HYDRA_SSH_PASSWORD", Description: "Wordlist for SSH password bruteforce"},
					{Text: "HYDRA_FTP_USER", Description: "Wordlist for FTP user bruteforce"},
					{Text: "HYDRA_FTP_PASSWORD", Description: "Wordlist for FTP password bruteforce"},
				}
				return prompt.FilterHasPrefix(subcommands, args[2], true)
			}
		}
		if len(args) == 4 {
			switch args[1] {
			case "nmap_switches":
				switch args[2] {
				case "SWEEP":
					subcommands := []prompt.Suggest{
						{Text: utils.Const_NMAP_SWEEP, Description: "Default switches"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "TCP_FULL":
					subcommands := []prompt.Suggest{
						{Text: utils.Const_NMAP_TCP_FULL, Description: "Default switches"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "TCP_STANDARD":
					subcommands := []prompt.Suggest{
						{Text: utils.Const_NMAP_TCP_STANDARD, Description: "Default switches"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "TCP_PROD":
					subcommands := []prompt.Suggest{
						{Text: utils.Const_NMAP_TCP_PROD, Description: "Default switches"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "TCP_VULN":
					subcommands := []prompt.Suggest{
						{Text: utils.Const_NMAP_TCP_VULN, Description: "Default switches"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "UDP_STANDARD":
					subcommands := []prompt.Suggest{
						{Text: utils.Const_NMAP_UDP_STANDARD, Description: "Default switches"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "UDP_PROD":
					subcommands := []prompt.Suggest{
						{Text: utils.Const_NMAP_UDP_PROD, Description: "Default switches"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				}

			case "wordlists":
				switch args[2] {
				case "FINGER_USER":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_FINGER_USER, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "FTP_USER":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_FTP_USER, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "SMTP":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_SMTP, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "SNMP":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_SNMP, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "DNS_BRUTEFORCE":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_DNS_BRUTEFORCE, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "HYDRA_SSH_USER":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_HYDRA_SSH_USER, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "HYDRA_SSH_PASSWORD":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_HYDRA_SSH_PWD, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "HYDRA_FTP_USER":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_HYDRA_FTP_USER, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				case "HYDRA_FTP_PASSWORD":
					subcommands := []prompt.Suggest{
						{Text: utils.WORDLIST_HYDRA_FTP_PWD, Description: "Default wordlist"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
				}
			}
		}

	// -----------------------------------------------------------------------------------
	// LOAD TARGETS
	// -----------------------------------------------------------------------------------
	case "load":
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "target", Description: "Add target addresses."},
				{Text: "alive", Description: "Add alive hosts."},
				{Text: "portscan", Description: "Add nmap port scan results from XML files."},
			}
			return prompt.FilterHasPrefix(subcommands, args[1], true)
		}
		if len(args) == 3 {
			switch args[1] {
			case "target":
				subcommands := []prompt.Suggest{
					{Text: "SINGLE", Description: "Directly add a single target via the CLI."},
					{Text: "MULTI", Description: "Upload multiple targets from a text file or folder."},
				}
				return prompt.FilterHasPrefix(subcommands, args[2], true)
			case "alive":
				subcommands := []prompt.Suggest{
					{Text: "SINGLE", Description: "Directly add a single alive host via the CLI."},
					{Text: "MULTI", Description: "Upload multiple alive hosts from a text file or folder."},
				}
				return prompt.FilterHasPrefix(subcommands, args[2], true)
			case "portscan":
				return fileCompleter(d)
			}
		}
		if len(args) == 4 {
			switch args[2] {
			case "SINGLE":
				return prompt.FilterContains(getTargetSuggestions(), args[3], true)
			case "MULTI":
				return fileCompleter(d)
			}
		}

	// -----------------------------------------------------------------------------------
	// SWEEP
	// -----------------------------------------------------------------------------------
	case "sweep":
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "PING", Description: "Perform a Ping Sweep."},
			}
			return prompt.FilterHasPrefix(subcommands, args[1], true)
		}
		if len(args) == 3 {
			return prompt.FilterContains(getSweepSuggestions(), args[2], true)
		}

	// -----------------------------------------------------------------------------------
	// PORTSCAN
	// -----------------------------------------------------------------------------------
	case "portscan":
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "TCP-FULL", Description: "Perform FULL TCP scan"},
				{Text: "TCP-STANDARD", Description: "Perform TCP scan (top 200)"},
				{Text: "TCP-PROD", Description: "Perform PROD TCP scan (T3, no scripts)"},
				{Text: "TCP-VULN-SCAN", Description: "Perform TCP VULN scan (vulscan.nse)"},
				{Text: "UDP-STANDARD", Description: "Perform UDP scan (common ports)"},
				{Text: "UDP-PROD", Description: "Perform PROD UDP scan (T3, no scripts)"},
			}
			return prompt.FilterHasPrefix(subcommands, args[1], true)
		}
		if len(args) == 3 {
			return prompt.FilterContains(getPortScanSuggestions(), args[2], true)
		}

	// -----------------------------------------------------------------------------------
	// ENUMERATION
	// -----------------------------------------------------------------------------------
	case "enumerate":
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "ALL", Description: "Automatically identify open services and enumerate them"},
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
			return prompt.FilterHasPrefix(subcommands, args[1], true)
		}
		if len(args) == 3 {
			third := args[2]
			subcommands := []prompt.Suggest{
				{Text: "DRY", Description: "Only show the commands that would be performed, without performing them"},
				{Text: "POLITE", Description: "Avoid bruteforcing"},
				{Text: "BRUTEFORCE", Description: "Include bruteforce scripts"},
			}
			return prompt.FilterHasPrefix(subcommands, third, true)
		}
		if len(args) == 4 {
			return prompt.FilterContains(getEnumerationSuggestions(), args[3], true)
		}

	// -----------------------------------------------------------------------------------
	// SPECIAL SCANS
	// -----------------------------------------------------------------------------------
	case "special":
		if len(args) == 2 {
			subcommands := []prompt.Suggest{
				{Text: "eyewitness", Description: "Take screenshots of websites, RDP services, and open VNC servers (KALI ONLY)"},
				{Text: "domain", Description: "Extract (windows) domain information from enumeration data"},
				{Text: "dns", Description: "Perform DNS enumeration"},
			}
			return prompt.FilterHasPrefix(subcommands, args[1], true)
		}
		if len(args) == 3 {
			switch args[1] {
				case "domain":			
					subcommands := []prompt.Suggest{
						{Text: "users", Description: "Extract users from enumeration data"},
						{Text: "hosts", Description: "Extract hosts from enumeration data"},
						{Text: "servers", Description: "Extract servers from enumeration data"},
					}
					return prompt.FilterHasPrefix(subcommands, args[2], true)
				case "dns":
					subcommands := []prompt.Suggest{
						{Text: "DISCOVERY", Description: "Enumerate DNS (nmap, dnsrecon, dnsenum)"},
						{Text: "BRUTEFORCE", Description: "Bruteforce DNS"},
						{Text: "BRUTEFORCE_REVERSE", Description: "Reverse Bruteforce DNS"},
					}
					return prompt.FilterHasPrefix(subcommands, args[2], true)
			}
		}
		if len(args) == 4 {
			switch args[1] {
				case "dns":
					subcommands := []prompt.Suggest{
						{Text: "domain.com", Description: "Target domain"},
					}
					return prompt.FilterHasPrefix(subcommands, args[3], true)
			}
		}
		if len(args) == 5 {
			switch args[1] {
				case "dns":
					switch args[2] {
						case "BRUTEFORCE_REVERSE":
							subcommands := []prompt.Suggest{
								{Text: "10.0.0.10", Description: "Base IP"},
							}
							return prompt.FilterHasPrefix(subcommands, args[4], true)
					}
			}
		}

	default:
		return []prompt.Suggest{}
	}

	return []prompt.Suggest{}
}

func getTargetSuggestions() []prompt.Suggest {
	// Default suggestions
	var target string = utils.Const_example_target_cidr
	var desc string = utils.Const_example_target_desc
	s := make([]prompt.Suggest, 1, 5)
	s[0] = prompt.Suggest{
		Text:        target,
		Description: desc,
	}

	// Parse address from network interface
	localInterfaces := utils.ParseLocalIP()
	for eth, ip := range localInterfaces {
		parsedIP, err := utils.ParseCIDR(ip)
		if err != nil {
			s = append(s, prompt.Suggest{
				Text:        parsedIP,
				Description: fmt.Sprintf("Subnet from interface: %s", eth),
			})
		}
	}

	return s
}

func getSweepSuggestions() []prompt.Suggest {
	toSweep := model.GetTargetByStep(utils.Config.DB, model.IMPORTED.String())
	s := make([]prompt.Suggest, 2, 5)
	s[0] = prompt.Suggest{
		Text:        "ALL",
		Description: "Sweep all targets (even those already sweeped)",
	}
	s[1] = prompt.Suggest{
		Text:		"TO_ANALYZE",
		Description: "Sweep only targets that haven't been sweeped yet",
	}

	for _, t := range toSweep {
		s = append(s, prompt.Suggest{
			Text:        t.Address,
			Description: fmt.Sprintf("Sweep: %s", t.Address),
		})
	}

	return s
}

func getPortScanSuggestions() []prompt.Suggest {
	toScan := model.GetHostByStep(utils.Config.DB, model.NEW.String())
	s := make([]prompt.Suggest, 2, 5)
	s[0] = prompt.Suggest{
		Text:        "ALL",
		Description: "Portscan all targets (even those already scanned)",
	}
	s[1] = prompt.Suggest{
		Text:		"TO_ANALYZE",
		Description: "Scan only targets that haven't been scanned yet",
	}

	for _, t := range toScan {
		s = append(s, prompt.Suggest{
			Text:        t.Address,
			Description: fmt.Sprintf("Portscan: %s", t.Address),
		})
	}

	return s
}

func getEnumerationSuggestions() []prompt.Suggest {
	toEnum := model.GetHostByStep(utils.Config.DB, model.SCANNED.String())
	s := make([]prompt.Suggest, 1, 5)
	s[0] = prompt.Suggest{
		Text:        "ALL",
		Description: "Enumerate all targets",
	}

	for _, t := range toEnum {
		s = append(s, prompt.Suggest{
			Text:        t.Address,
			Description: fmt.Sprintf("Enumerate: %s", t.Address),
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
		// if !f.IsDir() {
		// 	continue
		// }
		suggests = append(suggests, prompt.Suggest{Text: filepath.Join(dir, f.Name())})
	}
	return prompt.FilterHasPrefix(suggests, path, false)
}
