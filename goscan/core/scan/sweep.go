package scan

import (
	"fmt"
	"goscan/core/model"
	"goscan/core/utils"
	"os/exec"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------------------
// DISPATCHER
// ---------------------------------------------------------------------------------------
func ScanSweep(target string, kind string) {
	// Dispatch scan
	switch kind {
	case "PING":
		pingSweep(target)
	case "ARP":
		arpScan(target)
	case "ALL":
		arpScan(target)
		pingSweep(target)
	default:
		utils.Config.Log.LogError("Invalid type of scan")
		return
	}
	// Print hosts on screen
	utils.ShowHosts()
}

// ---------------------------------------------------------------------------------------
// SCANS
// ---------------------------------------------------------------------------------------
func pingSweep(target string) {
	// Create a new Scan and run it
	utils.Config.Log.LogInfo("Starting ping sweep...")
	name, folder, file, nmapArgs := "pingsweep", "sweep", "ping", "-n -sn"
	s := NewScan(name, target, folder, file, nmapArgs)
	s.RunNmap()

	// Parse nmap's output
	res := s.ParseOutput()

	// Identify live hosts
	for _, host := range res.Hosts {
		status := host.Status.State
		if status == "up" {
			addr := host.Addresses[0].Addr
			temp := model.Host{
				Address: addr,
				Status:  status,
			}
			AddHost(temp)
		}
	}
	utils.Config.Log.LogInfo("Ping sweep completed!")
}

func arpScan(target string) {
	// Directly run netdiscover
	utils.Config.Log.LogInfo("Starting ARP scan...")
	outfile := filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), "sweep/netdiscover")
	cmd := fmt.Sprintf("sudo netdiscover -r %s -P > %s && cat %s | grep -E '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}' | cut -d ' ' -f 2 | sort -u > %s", target, outfile, outfile, outfile)

	// Execute the command
	utils.Config.Log.LogDebug(fmt.Sprintf("Netdiscover command: %s", cmd))
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		utils.Config.Log.LogError("Failed to run netdiscover")
		return
	}

	// Identify live hosts
	for _, line := range strings.Split(strings.TrimSuffix(string(out[:]), "\n"), "\n") {
		if line != "" {
			temp := model.Host{
				Address: line,
				Status:  "up",
			}
			AddHost(temp)
		}
	}

	utils.Config.Log.LogInfo("ARP scan completed!")
}

// Add port to the list only if it's new
func AddHost(newHost model.Host) {
	existing := false
	for _, h := range utils.Config.Hosts {
		if h.Address == newHost.Address {
			existing = true
		}
	}
	if existing == false {
		utils.Config.Hosts = append(utils.Config.Hosts, newHost)
	}
}
