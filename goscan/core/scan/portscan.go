package scan

import (
	"goscan/core/model"
	"goscan/core/utils"
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
	for i := 0; i < len(utils.Config.Hosts); i++ {
		// Scan only if:
		//   - target is ALL
		//   - or if host is the selected one
		if target == "ALL" || target == utils.Config.Hosts[i].Address {
			go worker(name, &utils.Config.Hosts[i], folder, file, nmapArgs)
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

	// Extract ports and services
	for _, record := range res.Hosts {
		// Extract OS
		if len(record.Os.OsMatches) != 0 && record.Os.OsMatches[0].Name != "" {
			mutex.Lock()
			h.OS = record.Os.OsMatches[0].Name
			mutex.Unlock()
		}
		// Patse ports
		for _, port := range record.Ports {
			var tService model.Service
			var tPort model.Port
			// Extract service
			if port.Service.Name != "" {
				tService = model.Service{
					Name:    port.Service.Name,
					Version: port.Service.Version,
					Product: port.Service.Product,
					OsType:  port.Service.OsType,
				}
			}
			// Extract port
			tPort = model.Port{
				Number:   port.PortId,
				Protocol: port.Protocol,
				Status:   port.State.State,
				Service:  tService,
			}
			// If new port, add it to host
			mutex.Lock()
			h.AddPort(tPort)
			mutex.Unlock()
		}
	}
}
