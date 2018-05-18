package cli

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"goscan/core/scan"
	"goscan/core/utils"
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
	case "show":
		cmdShow(args)
	case "sweep":
		cmdSweep(args)
	case "portscan":
		cmdPortscan(args)
	case "enumerate":
		cmdEnumerate(args)
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
	go scan.ReportStatusEnum()
}

func cmdHelp() {
	utils.Config.Log.LogInfo("GoScan automates the scanning and enumeration steps of a penetration test")
	utils.Config.Log.LogInfo("Available commands:")

	data := [][]string{
		[]string{"Set output folder", "set_output_folder <PATH>"},
		[]string{"Ping Sweep", "sweep <TYPE> <TARGET>"},
		[]string{"Port Scan", "portscan <TYPE> <TARGET>"},
		[]string{"Service Enumeration", "enumerate <TYPE> <POLITE/AGGRESSIVE> <TARGET>"},
		[]string{"Show live hosts", "show hosts"},
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Command", "Syntax"})
	table.SetAlignment(3)
	table.SetAutoWrapText(false)
	table.AppendBulk(data)
	table.Render()
}

func cmdShow(args []string) {
	what, _ := utils.ParseNextArg(args)
	switch what {
	case "hosts":
		utils.ShowHosts()
	}
}

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
	// Perform port scan
	scan.ScanEnumerate(target, polite, kind)
}
