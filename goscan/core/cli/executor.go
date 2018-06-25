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
		case "help":
			cmdHelp()
		case "sweep":
			cmdSweep(args)
		case "portscan":
			cmdPortscan(args)
		case "enumerate":
			cmdEnumerate(args)
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


// ---------------------------------------------------------------------------------------
// HELP
// ---------------------------------------------------------------------------------------
func cmdHelp() {
	utils.Config.Log.LogInfo("GoScan automates the scanning and enumeration steps of a penetration test")
	utils.Config.Log.LogInfo("Available commands:")

	data := [][]string{
		[]string{"Set output folder", "set_output_folder <PATH>"},
		[]string{"Ping Sweep", "sweep <TYPE> <TARGET>"},
		[]string{"Port Scan", "portscan <TYPE> <TARGET>"},
		[]string{"Service Enumeration", "enumerate <TYPE> <POLITE/AGGRESSIVE> <TARGET>"},
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
