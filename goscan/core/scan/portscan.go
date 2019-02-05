package scan

import (
	"fmt"
	go_nmap "github.com/lair-framework/go-nmap"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/utils"
	"time"
)

// ---------------------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------------------
var notificationDelay time.Duration = time.Duration(utils.Const_notification_delay_unit) * time.Second
var ScansList = []*NmapScan{}

// ---------------------------------------------------------------------------------------
// DISPATCHER
// ---------------------------------------------------------------------------------------
func ScanPort(kind string, target string) {
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
	case "TCP-PROD":
		utils.Config.Log.LogInfo("Starting production TCP port scan")
		file, nmapArgs := "tcp_prod", utils.Const_NMAP_TCP_PROD
		execScan(file, target, folder, file, nmapArgs)
	case "TCP-VULN-SCAN":
		utils.Config.Log.LogInfo("Starting TCP vuln scan")
		file, nmapArgs := "tcp_vuln", utils.Const_NMAP_TCP_VULN
		execScan(file, target, folder, file, nmapArgs)
	case "UDP-STANDARD":
		utils.Config.Log.LogInfo("Starting UDP port scan (common ports)")
		file, nmapArgs := "udp_standard", utils.Const_NMAP_UDP_STANDARD
		execScan(file, target, folder, file, nmapArgs)
	case "UDP-PROD":
		utils.Config.Log.LogInfo("Starting production UDP port scan (common ports)")
		file, nmapArgs := "udp_prod", utils.Const_NMAP_UDP_PROD
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
		//   - or if target is TO_ANALYZE and host still need to be analyzed
		//   - or if host is the selected one
		if target == "ALL" || 
		   (target == "TO_ANALYZE" && h.Step == model.NEW.String()) || 
		   target == h.Address {
			temp := h
			fname := fmt.Sprintf("%s_%s", file, h.Address)
			go worker(name, &temp, folder, fname, nmapArgs)
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
	if res != nil {
		for _, record := range res.Hosts {
			ProcessResults(h, record)
		}
	}
}

func ProcessResults(h *model.Host, record go_nmap.Host) {
	// -------------------------------------------------------------------------------
	// Extract OS
	// -------------------------------------------------------------------------------
	if len(record.Os.OsMatches) != 0 && record.Os.OsMatches[0].Name != "" {
		model.Mutex.Lock()
		osname := record.Os.OsMatches[0].Name
		h.OS = osname
		utils.Config.DB.Save(&h)
		model.Mutex.Unlock()
	}
	// -------------------------------------------------------------------------------
	// Parse ports
	// -------------------------------------------------------------------------------
	for _, port := range record.Ports {
		// Create new port, will add to db if new
		np, _ := model.AddPort(utils.Config.DB, port.PortId, port.Protocol, port.State.State, h)

		// Add Service
		if port.Service.Name != "" {
			model.AddService(utils.Config.DB, port.Service.Name, port.Service.Version, port.Service.Product, port.Service.OsType, np, np.ID)
		}
	}

	// -------------------------------------------------------------------------------
	// Update status of host
	// -------------------------------------------------------------------------------
	model.Mutex.Lock()
	h.Step = model.SCANNED.String()
	utils.Config.DB.Save(&h)
	model.Mutex.Unlock()
}
