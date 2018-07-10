package cli

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/scan"
	"github.com/marco-lancini/goscan/core/utils"
	"github.com/olekukonko/tablewriter"
	"os"
)

func Executor(s string) {
	// Parse cmd
	cmd, args := utils.ParseCmd(s)

	// Execute commands
	switch cmd {
		case "set_target":
			cmdSetTarget(args)
		case "set_output_folder":
			cmdSetOutputFolder(args)
		case "set_nmap_switches":
			cmdSetNmapSwitches(args)
		case "set_wordlists":
			cmdSetWordlists(args)
		case "help":
			cmdHelp()
		case "sweep":
			cmdSweep(args)
		case "portscan":
			cmdPortscan(args)
		case "enumerate":
			cmdEnumerate(args)
		case "dns":
			cmdDNS(args)
		case "domain":
			cmdDomain(args)
		case "db":
			cmdDB(args)
		case "show":
			cmdShow(args)
		case "exit", "quit":
			os.Exit(0)
			return
		case "":
		default:
			return
	}

	// Start checking for running scans
	go scan.ReportStatusNmap()
	go scan.ReportStatusEnum()
}


// ---------------------------------------------------------------------------------------
// SET
// ---------------------------------------------------------------------------------------
func cmdSetTarget(args []string) bool {
	if len(args) != 1 {
		utils.Config.Log.LogError("Invalid command provided")
		return false
	}
	ip, _ := utils.ParseNextArg(args)
	cidr := utils.ParseCIDR(ip)
	if cidr == "" {
		utils.Config.Log.LogError("Invalid CIDR provided")
		return false
	}
	utils.Config.Log.LogInfo(fmt.Sprintf("Selected target: %s", cidr))
	utils.Config.Target = cidr
	return true
}

func cmdSetOutputFolder(args []string) {
	if len(args) != 1 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	folder, _ := utils.ParseNextArg(args)
	utils.Config.Outfolder = folder
	utils.EnsureDir(utils.Config.Outfolder)
}

func cmdSetNmapSwitches(args []string) {
	// Get kind
	kind, args := utils.ParseNextArg(args)
	// Get all switches
	switches := utils.ParseAllArgs(args)
	// Update value
	switch kind {
		case "SWEEP":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_SWEEP))
			utils.Const_NMAP_SWEEP = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_SWEEP))

		case "TCP_FULL":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_TCP_FULL))
			utils.Const_NMAP_TCP_FULL = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_TCP_FULL))

		case "TCP_STANDARD":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_TCP_STANDARD))
			utils.Const_NMAP_TCP_STANDARD = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_TCP_STANDARD))

		case "TCP_VULN":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_TCP_VULN))
			utils.Const_NMAP_TCP_VULN = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_TCP_VULN))

		case "UDP_STANDARD":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_UDP_STANDARD))
			utils.Const_NMAP_UDP_STANDARD = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_UDP_STANDARD))
	}
}

func cmdSetWordlists(args []string) {
	// Get kind
	kind, args := utils.ParseNextArg(args)
	// Get wordlist
	switches, _ := utils.ParseNextArg(args)
	// Update value
	switch kind {
		case "FINGER_USER":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_FINGER_USER))
			utils.WORDLIST_FINGER_USER = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_FINGER_USER))

		case "FTP_USER":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_FTP_USER))
			utils.WORDLIST_FTP_USER = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_FTP_USER))

		case "SMTP":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_SMTP))
			utils.WORDLIST_SMTP = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_SMTP))

		case "SNMP":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_SNMP))
			utils.WORDLIST_SNMP = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_SNMP))

		case "DNS_BRUTEFORCE":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_DNS_BRUTEFORCE))
			utils.WORDLIST_DNS_BRUTEFORCE = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_DNS_BRUTEFORCE))
		
		case "HYDRA_SSH_USER":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_HYDRA_SSH_USER))
			utils.WORDLIST_HYDRA_SSH_USER = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_HYDRA_SSH_USER))

		case "HYDRA_SSH_PASSWORD":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_HYDRA_SSH_PWD))
			utils.WORDLIST_HYDRA_SSH_PWD = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_HYDRA_SSH_PWD))

		case "HYDRA_FTP_USER":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_HYDRA_FTP_USER))
			utils.WORDLIST_HYDRA_FTP_USER = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_HYDRA_FTP_USER))
		
		case "HYDRA_FTP_PASSWORD":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.WORDLIST_HYDRA_FTP_PWD))
			utils.WORDLIST_HYDRA_FTP_PWD = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.WORDLIST_HYDRA_FTP_PWD))
	}
}


// ---------------------------------------------------------------------------------------
// HELP
// ---------------------------------------------------------------------------------------
func cmdHelp() {
	utils.Config.Log.LogInfo("GoScan automates the scanning and enumeration steps of a penetration test")
	utils.Config.Log.LogInfo("Available commands:")

	data := [][]string{
		[]string{"Set output folder", "set_output_folder <PATH>"},
		[]string{"Modify the default nmap switches", "set_nmap_switches <SWEEP/TCP_FULL/TCP_STANDARD/TCP_VULN/UDP_STANDARD>"},
		[]string{"Modify the default wordlists", "set_wordlists <FINGER_USER/FTP_USER/...>"},
		[]string{"Ping Sweep", "sweep <TYPE> <TARGET>"},
		[]string{"Port Scan", "portscan <TYPE> <TARGET>"},
		[]string{"Service Enumeration", "enumerate <TYPE> <POLITE/AGGRESSIVE> <TARGET>"},
		[]string{"DNS Enumeration", "dns <DISCOVERY/BRUTEFORCE/BRUTEFORCE_REVERSE> <DOMAIN> [<BASE_IP>]"},
		[]string{"Extract (windows) domain information from enumeration data", "domain <users/hosts/servers>"},
		[]string{"Show live hosts", "show hosts"},
		[]string{"Show detailed ports information", "show ports"},
		[]string{"Manage DB", "db <reset>"},
		[]string{"Exit this program", "exit"},
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Command", "Syntax"})
	table.SetAlignment(3)
	table.SetAutoWrapText(false)
	table.AppendBulk(data)
	table.Render()
}


// ---------------------------------------------------------------------------------------
// SCAN
// ---------------------------------------------------------------------------------------
func cmdSweep(args []string) {
	if len(args) != 2 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	// Get type of scan
	kind, args := utils.ParseNextArg(args)
	// Get target and update global config
	target, _ := utils.ParseNextArg(args)
	check := cmdSetTarget(args)
	if check == false {
		return
	}
	// Perform ping sweep
	scan.ScanSweep(target, kind)
}

func cmdPortscan(args []string) {
	if len(args) != 2 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	// Get type of scan
	kind, args := utils.ParseNextArg(args)
	// Get target host
	target, _ := utils.ParseNextArg(args)
	// Perform port scan
	scan.ScanPort(target, kind)
}

func cmdEnumerate(args []string) {
	if len(args) != 3 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	// Get type of scan
	kind, args := utils.ParseNextArg(args)
	// Get politeness
	polite, args := utils.ParseNextArg(args)
	// Get target host
	target, _ := utils.ParseNextArg(args)
	// Perform enumeration
	scan.ScanEnumerate(target, polite, kind)
}

func cmdDNS(args []string) {
	if len(args) < 2 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	// Get type of scan
	kind, args := utils.ParseNextArg(args)
	// Get target domain
	target, args := utils.ParseNextArg(args)
	// Get base ip
	baseIP := ""
	if kind == "BRUTEFORCE_REVERSE" {
		baseIP, _ = utils.ParseNextArg(args)
	}
	// Perform port scan
	scan.ScanDNS(target, kind, baseIP)
}

func cmdDomain(args []string) {
	if len(args) != 1 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	// Get type
	kind, _ := utils.ParseNextArg(args)
	// Gather data
	scan.GatherDomain(kind)
}


// ---------------------------------------------------------------------------------------
// DB
// ---------------------------------------------------------------------------------------
func cmdDB(args []string) {
	if len(args) != 1 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	what, _ := utils.ParseNextArg(args)
	switch what {
		case "reset":
			utils.Config.Log.LogInfo("Resetting DB")
			model.ResetDB(utils.Config.DB)
	}
}


// ---------------------------------------------------------------------------------------
// SHOW
// ---------------------------------------------------------------------------------------
func cmdShow(args []string) {
	if len(args) != 1 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	what, _ := utils.ParseNextArg(args)
	switch what {
		case "hosts":
			ShowHosts()
		case "ports":
			ShowPorts()
	}
}

func ShowHosts() {
	hosts := model.GetAllHosts(utils.Config.DB)
	if len(hosts) == 0 {
		utils.Config.Log.LogError("No hosts are up!")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Address", "Status", "OS", "Info", "Ports"})
	table.SetRowLine(true)
	table.SetAlignment(3)
	table.SetAutoWrapText(false)

	for _, h := range hosts {
		rAddress := h.Address
		rStatus := h.Status
		rOS := h.OS
		rInfo := h.Info
		rPorts := ""
		for _, tPort := range h.GetPorts(utils.Config.DB) {
			tService := tPort.GetService(utils.Config.DB)
			rPorts = fmt.Sprintf("%s* %s", rPorts, tPort.String())
			if tService.Name != "" {
				rPorts = fmt.Sprintf("%s: %s\n", rPorts, tService.String())
			} else {
				rPorts = fmt.Sprintf("%s\n", rPorts)
			}
		}
		v := []string{rAddress, rStatus, rOS, rInfo, rPorts}
		table.Append(v)
	}
	table.Render()
}

func ShowPorts() {
	hosts := model.GetAllHosts(utils.Config.DB)
	if len(hosts) == 0 {
		utils.Config.Log.LogError("No hosts are up!")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Host", "Port", "Status", "Service", "Updated At"})
	table.SetRowLine(true)
	table.SetAlignment(3)
	table.SetAutoWrapText(false)

	for _, h := range hosts {
		rAddress := h.Address
		for _, tPort := range h.GetPorts(utils.Config.DB) {
			tService := tPort.GetService(utils.Config.DB)
			rPort := fmt.Sprintf("%d/%s", tPort.Number, tPort.Protocol)
			rStatus := tPort.Status
			rUpdatedAt := tPort.UpdatedAt.String()

			rService := tService.Name
			if tService.Product != "" {
				rService = fmt.Sprintf("%s [%s %s]", rService, tService.Product, tService.Version)
				if tService.OsType != "" {
					rService = fmt.Sprintf("%s [%s]", rService, tService.OsType)
				}
			}

			v := []string{rAddress, rPort, rStatus, rService, rUpdatedAt}
			table.Append(v)
		}
	}
	table.Render()
}
