package scan

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/utils"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------------------
var mutex sync.Mutex
var notificationDelay time.Duration = time.Duration(utils.Const_notification_delay_unit) * time.Second
var ScansList = []*NmapScan{}

// ---------------------------------------------------------------------------------------
// DISPATCHER
// ---------------------------------------------------------------------------------------
func ScanPort(target string, kind string) {
	folder := "portscan"

	// Dispatch scan
	switch kind {
	case "TCP-FULL":
		utils.Config.Log.LogInfo("Starting full TCP port scan")
		file, nmapArgs := "tcp_full", utils.Const_NMAP_TCP_FULL
		execScan(file, target, folder, file, nmapArgs)
	case "TCP-STANDARD":
		utils.Config.Log.LogInfo("Starting top 200 TCP port scan")
		file, nmapArgs := "tcp_standard", utils.Const_NMAP_TCP_STANDARD
		execScan(file, target, folder, file, nmapArgs)
	case "TCP-VULN-SCAN":
		utils.Config.Log.LogInfo("Starting TCP vuln scan")
		file, nmapArgs := "tcp_vuln", utils.Const_NMAP_TCP_VULN
		execScan(file, target, folder, file, nmapArgs)
	case "UDP-STANDARD":
		utils.Config.Log.LogInfo("Starting UDP port scan (common ports)")
		file, nmapArgs := "udp_standard", utils.Const_NMAP_UDP_STANDARD
		execScan(file, target, folder, file, nmapArgs)
	default:
		utils.Config.Log.LogError("Invalid type of scan")
		return
	}
}

// ---------------------------------------------------------------------------------------
// SCAN LAUNCHER
// ---------------------------------------------------------------------------------------
func execScan(name, target, folder, file, nmapArgs string) {
	hosts := model.GetAllHosts(utils.Config.DB)
	for _, h := range hosts {
		// Scan only if:
		//   - target is ALL
		//   - or if host is the selected one
		if target == "ALL" || target == h.Address {
			temp := h
			go worker(name, &temp, folder, file, nmapArgs)
		}
	}
}

// ---------------------------------------------------------------------------------------
// WORKER
// ---------------------------------------------------------------------------------------
func worker(name string, h *model.Host, folder string, file string, nmapArgs string) {
	// Instantiate new NmapScan
	s := NewScan(name, h.Address, folder, file, nmapArgs)
	ScansList = append(ScansList, s)

	// Run the scan
	s.RunNmap()

	// Parse nmap's output
	res := s.ParseOutput()

	// Get previously identified ports
	oldPorts := h.GetMostRecentPorts(utils.Config.DB)

	// Extract ports and services
	newPorts := []model.Port{}
	for _, record := range res.Hosts {
		// -------------------------------------------------------------------------------
		// Extract OS
		// -------------------------------------------------------------------------------
		if len(record.Os.OsMatches) != 0 && record.Os.OsMatches[0].Name != "" {
			mutex.Lock()
			osname := record.Os.OsMatches[0].Name
			h.OS = osname
			utils.Config.DB.Save(&h)
			mutex.Unlock()
		}

		// -------------------------------------------------------------------------------
		// Parse ports
		// -------------------------------------------------------------------------------
		for _, port := range record.Ports {
			// Create new port, will add to db if new
			np, duplicate := model.AddPort(utils.Config.DB, port.PortId, port.Protocol, port.State.State, h)
			// Check if new or duplicate
			if duplicate == true {
				// Old port, update "UpdatedAt" field
				mutex.Lock()
				originalPort := np.FindOriginalPort(utils.Config.DB)
				originalPort.UpdatedAt = time.Now()
				utils.Config.DB.Save(originalPort)
				mutex.Unlock()
				// Remove port from oldPorts
				oldPorts = removePort(oldPorts, originalPort)
			} else {
				newPorts = append(newPorts, *np)
			}

			// Add Service
			if port.Service.Name != "" {
				model.AddService(utils.Config.DB, port.Service.Name, port.Service.Version, port.Service.Product, port.Service.OsType, np)
			}
		}
	}
	// -----------------------------------------------------------------------------------
	// Compare ports
	// -----------------------------------------------------------------------------------
	for _, p := range newPorts {
		utils.Config.Log.LogNotify(fmt.Sprintf("New port found: %s", p.String()))
	}
	for _, p := range oldPorts {
		utils.Config.Log.LogError(fmt.Sprintf("Port now closed: %s", p.String()))
	}
}

func removePort(ports []model.Port, toDelete *model.Port) []model.Port {
	filteredPorts := []model.Port{}
	for _, p := range ports {
		if toDelete.Equal(p) == false {
			filteredPorts = append(filteredPorts, p)
		}
	}
	return filteredPorts
}
