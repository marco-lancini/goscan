package scan

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"github.com/marco-lancini/goscan/core/model"
	"path/filepath"
)

// ---------------------------------------------------------------------------------------
// DISPATCHER
// ---------------------------------------------------------------------------------------
func EyeWitness() {
	// Set output folder
	folder_eyewitness := filepath.Join(utils.Config.Outfolder, "eyewitness")
	folder_results := filepath.Join(folder_eyewitness, "results")
	file_source := filepath.Join(folder_eyewitness, "source.txt")
	utils.EnsureDir(folder_eyewitness)
	utils.RemoveDir(folder_results)

	// Extract HTTP, RDP, VNC ports from database
	http := extractService("%http%")
	rdp := extractService("%rdp%")
	vnc := extractService("%vnc%")
	// Merge in single slice
	targets := append(http, rdp...)
	targets = append(targets, vnc...)
	// Save to temp file
	utils.WriteArrayToFile(file_source, targets)

	// Run EyeWitness
	utils.ShellCmd(fmt.Sprintf("EyeWitness.py --all-protocols --active-scan --no-dns --threads 5 -d %s -f %s", folder_results, file_source))
	utils.Config.Log.LogNotify(fmt.Sprintf("Results are stored in: %s", folder_results))
	utils.ShellCmd(fmt.Sprintf("firefox %s/report.html &", folder_results))
}

func extractService(srv string) []string {
	var targets []string
	services := model.GetServiceByName(utils.Config.DB, srv)

	for _, srv := range services {
		port := srv.GetPort(utils.Config.DB)
		host := port.GetHost(utils.Config.DB)
		t := fmt.Sprintf("%s:%d", host.Address, port.Number)
		targets = append(targets, t)
		utils.Config.Log.LogInfo(fmt.Sprintf("Identified service: %s - %s", srv.Name, t))
	}

	return targets
}