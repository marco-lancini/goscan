package cli

import (
	"bufio"
	"fmt"
	"github.com/marco-lancini/goscan/core/enum"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/scan"
	"github.com/marco-lancini/goscan/core/utils"
	"github.com/olekukonko/tablewriter"
	"io/ioutil"
	"os"
	"path/filepath"
)

func Executor(s string) {
	// Parse cmd
	cmd, args := utils.ParseCmd(s)

	// Execute commands
	switch cmd {
	case "load":
		cmdLoad(args)
	case "sweep":
		cmdSweep(args)
	case "portscan":
		cmdPortscan(args)
	case "enumerate":
		cmdEnumerate(args)
	case "special":
		cmdSpecial(args)
	case "show":
		cmdShow(args)
	case "set":
		cmdSet(args)
	case "help":
		cmdHelp()
	case "exit", "quit":
		os.Exit(0)
		return
	case "":
	default:
		return
	}

	// Start checking for running scans
	go scan.ReportStatusNmap()
	go enum.ReportStatusEnum()
}

// ---------------------------------------------------------------------------------------
// HELP
// ---------------------------------------------------------------------------------------
func cmdHelp() {
	utils.Config.Log.LogInfo("GoScan automates the scanning and enumeration steps of a penetration test")
	utils.Config.Log.LogInfo("Available commands:")

	data := [][]string{
		[]string{"Load target", "Add a single target via the CLI (must be a /32)", "load target SINGLE <IP>"},
		[]string{"Load target", "Upload multiple targets from a text file or folder", "load target MULTI <path-to-file>"},

		[]string{"Host Discovery", "Perform a Ping Sweep", "sweep <TYPE> <TARGET>"},
		[]string{"Load Host Discovery", "Add a single alive host via the CLI (must be a /32)", "load alive SINGLE <IP>"},
		[]string{"Load Host Discovery", "Upload multiple alive hosts from a text file or folder", "load alive MULTI <path-to-file>"},

		[]string{"Port Scan", "Perform a port scan", "portscan <TYPE> <TARGET>"},
		[]string{"Load Port Scan", "Upload nmap port scan results from XML files or folder", "load portscan <path-to-file>"},

		[]string{"Service Enumeration", "Dry Run (only show commands, without performing them", "enumerate <TYPE> DRY <TARGET>"},
		[]string{"Service Enumeration", "Perform enumeration of detected services", "enumerate <TYPE> <POLITE/AGGRESSIVE> <TARGET>"},

		[]string{"Special Scan - EyeWitness", "Take screenshots of websites, RDP services, and open VNC servers (KALI ONLY)", "special eyewitness"},

		[]string{"Special Scan - Domain Info", "Extract Windows domain information from enumeration data", "special domain <users/hosts/servers>"},

		[]string{"Special Scan - DNS", "Enumerate DNS (nmap, dnsrecon, dnsenum)", "special dns DISCOVERY <domain>"},
		[]string{"Special Scan - DNS", "Bruteforce DNS", "special dns BRUTEFORCE <domain>"},
		[]string{"Special Scan - DNS", "Reverse Bruteforce DNS", "special dns BRUTEFORCE_REVERSE <domain> <base_IP>"},

		[]string{"Show", "Show targets", "show targets"},
		[]string{"Show", "Show live hosts", "show hosts"},
		[]string{"Show", "Show detailed ports information", "show ports"},

		[]string{"Utils", "Set configs from file", "set config_file <PATH>"},
		[]string{"Utils", "Set output folder", "set output_folder <PATH>"},
		[]string{"Utils", "Modify the default nmap switches", "set nmap_switches <SWEEP/TCP_FULL/TCP_STANDARD/TCP_VULN/UDP_STANDARD> <SWITCHES>"},
		[]string{"Utils", "Modify the default wordlists", "set wordlists <FINGER_USER/FTP_USER/...> <PATH>"},

		[]string{"Utils", "Exit this program", "exit"},
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Area", "Command", "Syntax"})
	table.SetAlignment(3)
	table.SetAutoWrapText(false)
	table.AppendBulk(data)
	table.Render()
}

// ---------------------------------------------------------------------------------------
// LOAD
// ---------------------------------------------------------------------------------------
func cmdLoad(args []string) bool {
	// Parse kind of operation
	kind, args := utils.ParseNextArg(args)

	// Portscan has a different syntax (and logic)
	if kind == "portscan" {
		src, _ := utils.ParseNextArg(args)
		return loadPortscan(src)
	}

	// "Target" and "Alive" have common logic instead
	how, args := utils.ParseNextArg(args)
	src, _ := utils.ParseNextArg(args)

	switch how {
	case "SINGLE":
		// Parse address
		target, parsed := utils.ParseAddress(src)
		if parsed == false {
			utils.Config.Log.LogError("Invalid address provided")
			return false
		}
		// Save to DB based on what to load
		switch kind {
		case "target":
			utils.Config.Log.LogInfo(fmt.Sprintf("Imported target: %s", target))
			model.AddTarget(utils.Config.DB, target, model.IMPORTED.String())
		case "alive":
			utils.Config.Log.LogInfo(fmt.Sprintf("Imported alive host: %s", target))
			model.AddHost(utils.Config.DB, target, "up", model.NEW.String())
		}
	case "MULTI":
		// If it's a folder, iterate through all the files contained in there
		fpath, err := os.Stat(src)
		if err != nil {
			utils.Config.Log.LogError(fmt.Sprintf("Error while trying to read file: %s", fpath))
		} else {
			if fpath.IsDir() {
				dir := filepath.Dir(src)
				files, err := ioutil.ReadDir(dir)
				if err != nil {
					utils.Config.Log.LogError(fmt.Sprintf("Error while listing content of directory: %s", src))
				}
				for _, f := range files {
					if !f.IsDir() {
						loadFile(kind, filepath.Join(dir, f.Name()))
					}
				}
			} else {
				// If it's a file, import it straight away
				loadFile(kind, src)
			}
		}
	}
	return true
}

func loadFile(kind string, src string) {
	// Open source file
	file, err := os.Open(src)
	if err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Error while reading source file (%s): %s", src, err))
	}
	defer file.Close()
	// Read line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		addr := scanner.Text()
		// Parse address
		target, parsed := utils.ParseAddress(addr)
		if parsed == false {
			utils.Config.Log.LogError(fmt.Sprintf("Invalid address provided: %s. Skipping", target))
			continue
		}
		// Save to DB based on what to load
		utils.Config.Log.LogInfo(fmt.Sprintf("Importing: %s", addr))
		switch kind {
		case "target":
			model.AddTarget(utils.Config.DB, target, model.IMPORTED.String())
		case "alive":
			model.AddHost(utils.Config.DB, target, "up", model.NEW.String())
		}
	}
	// Error while reading the file
	if err := scanner.Err(); err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Error while reading source file: %s", err))
	}
}

func loadPortscan(src string) bool {
	// If it's a folder, iterate through all the files contained in there
	fpath, _ := os.Stat(src)
	if fpath.IsDir() {
		err := filepath.Walk(src,
			func(path string, info os.FileInfo, err error) error {
			if err != nil {
				utils.Config.Log.LogError(fmt.Sprintf("Error while listing content of directory: %s", src))
				return err
			}
			t, _ := os.Stat(path)
			if filepath.Ext(t.Name()) == ".xml" {
				loadNmapXML(path)
			}
			return nil
		})
		if err != nil {
			return false
		}
	} else {
		// If it's a file, import it straight away
		if filepath.Ext(fpath.Name()) != ".xml" {
			utils.Config.Log.LogError(fmt.Sprintf("Please provide an nmap XML file"))
			return false
		}
		loadNmapXML(src)
	}
	return true
}

func loadNmapXML(fname string) {
	utils.Config.Log.LogInfo(fmt.Sprintf("Loading: %s", fname))

	// Parse nmap's output
	res := scan.ParseOutput(fname)
	if res != nil {
		for _, record := range res.Hosts {
			// Retrieve host
			h := model.GetHostByAddress(utils.Config.DB, record.Addresses[0].Addr)
			if h == nil || h.Address == "" {
				// If host doesn't exist yet (because we are importing from XML), create a record
				h = model.AddHost(utils.Config.DB, record.Addresses[0].Addr, record.Status.State, model.NEW.String())
			}
			// Extract info and assign to host
			scan.ProcessResults(h, record)
		}
	}
}

// ---------------------------------------------------------------------------------------
// SCAN
// ---------------------------------------------------------------------------------------
func cmdSweep(args []string) {
	// Check arguments length to ensure all required options have been provided
	if len(args) != 2 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	// Parse kind of scan and target
	kind, args := utils.ParseNextArg(args)
	target, _ := utils.ParseNextArg(args)
	// Perform ping sweep
	scan.ScanSweep(kind, target)
}

func cmdPortscan(args []string) {
	// Check arguments length to ensure all required options have been provided
	if len(args) != 2 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	// Parse kind of scan and target host
	kind, args := utils.ParseNextArg(args)
	target, _ := utils.ParseNextArg(args)
	// Perform port scan
	scan.ScanPort(kind, target)
}

func cmdEnumerate(args []string) {
	// Check arguments length to ensure all required options have been provided
	if len(args) != 3 {
		utils.Config.Log.LogError("Invalid command provided")
		return
	}
	// Parse type of scan, politeness, and target host
	kind, args := utils.ParseNextArg(args)
	polite, args := utils.ParseNextArg(args)
	target, _ := utils.ParseNextArg(args)
	// Perform enumeration
	enum.ScanEnumerate(kind, polite, target)
}

// ---------------------------------------------------------------------------------------
// SPECIAL SCANS
// ---------------------------------------------------------------------------------------
func cmdSpecial(args []string) {
	what, args := utils.ParseNextArg(args)
	switch what {
		case "eyewitness":
			scan.EyeWitness()
		case "domain":
			kind, _ := utils.ParseNextArg(args)
			scan.GatherDomain(kind)
		case "dns":
			// Get type of scan and target domain
			kind, args := utils.ParseNextArg(args)
			target, args := utils.ParseNextArg(args)
			// Get base ip
			baseIP := ""
			if kind == "BRUTEFORCE_REVERSE" {
				baseIP, _ = utils.ParseNextArg(args)
			}
			// Perform port scan
			scan.ScanDNS(target, kind, baseIP)
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
	case "targets":
		ShowTargets()
	case "hosts":
		ShowHosts()
	case "ports":
		ShowPorts()
	}
}

func ShowTargets() {
	targets := model.GetAllTargets(utils.Config.DB)
	if len(targets) == 0 {
		utils.Config.Log.LogError("No targets imported")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Address", "Step"})
	table.SetRowLine(true)
	table.SetAlignment(3)
	table.SetAutoWrapText(false)

	for _, h := range targets {
		rAddress := h.Address
		rStep := h.Step
		v := []string{rAddress, rStep}
		table.Append(v)
	}
	table.Render()
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
	table.SetHeader([]string{"Host", "Port", "Status", "Service"})
	table.SetRowLine(true)
	table.SetAlignment(3)
	table.SetAutoWrapText(false)

	for _, h := range hosts {
		rAddress := h.Address
		for _, tPort := range h.GetPorts(utils.Config.DB) {
			tService := tPort.GetService(utils.Config.DB)
			rPort := fmt.Sprintf("%d/%s", tPort.Number, tPort.Protocol)
			rStatus := tPort.Status

			rService := tService.Name
			if tService.Product != "" {
				rService = fmt.Sprintf("%s [%s %s]", rService, tService.Product, tService.Version)
				if tService.OsType != "" {
					rService = fmt.Sprintf("%s [%s]", rService, tService.OsType)
				}
			}
			v := []string{rAddress, rPort, rStatus, rService}
			table.Append(v)
		}
	}
	table.Render()
}

// ---------------------------------------------------------------------------------------
// UTILS
// ---------------------------------------------------------------------------------------
// Set configs from file
func SetConfigFile(fname string) {
	// Open source file
	file, err := os.Open(fname)
	if err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Error while reading source file (%s): %s", fname, err))
	}
	defer file.Close()
	// Read line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		cmd := scanner.Text()
		Executor(cmd)
	}
	// Error while reading the file
	if err := scanner.Err(); err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Error while reading source file: %s", err))
	}
}

func cmdSet(args []string) {
	// // Check arguments length to ensure all required options have been provided
	// if len(args) != 1 {
	// 	utils.Config.Log.LogError("Invalid command provided")
	// 	return
	// }

	// Parse kind of operation
	kind, args := utils.ParseNextArg(args)
	switch kind {
	case "config_file":
		fname, _ := utils.ParseNextArg(args)
		SetConfigFile(fname)
	case "output_folder":
		folder, _ := utils.ParseNextArg(args)
		utils.ChangeOutFolder(folder)
	case "nmap_switches":
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
		case "TCP_PROD":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_TCP_PROD))
			utils.Const_NMAP_TCP_PROD = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_TCP_PROD))
		case "TCP_VULN":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_TCP_VULN))
			utils.Const_NMAP_TCP_VULN = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_TCP_VULN))
		case "UDP_STANDARD":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_UDP_STANDARD))
			utils.Const_NMAP_UDP_STANDARD = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_UDP_STANDARD))
		case "UDP_PROD":
			utils.Config.Log.LogInfo(fmt.Sprintf("Previous value: %s", utils.Const_NMAP_UDP_PROD))
			utils.Const_NMAP_UDP_PROD = switches
			utils.Config.Log.LogNotify(fmt.Sprintf("Updated value: %s", utils.Const_NMAP_UDP_PROD))
		}
	case "wordlists":
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
}
