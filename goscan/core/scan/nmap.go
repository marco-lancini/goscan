package scan

import (
	"fmt"
	go_nmap "github.com/lair-framework/go-nmap"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/utils"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"time"
)

// ---------------------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------------------
const (
	null = iota
	not_started
	in_progress
	failed
	done
	finished
)

// ---------------------------------------------------------------------------------------
// NMAP INTERACTION
// ---------------------------------------------------------------------------------------
type NmapScan model.Scan

// Constructor for NmapScan
func NewScan(name, target, folder, file, nmapArgs string) *NmapScan {
	// Create a Scan
	s := &NmapScan{
		Name:   name,
		Target: target,
		Status: not_started,
	}
	// Construct output path and create if it doesn't exist
	s.Outfolder = filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), folder)
	s.Outfile = filepath.Join(s.Outfolder, file)
	utils.EnsureDir(s.Outfolder)
	// Construct command
	s.Cmd = s.constructCmd(nmapArgs)

	return s
}

func (s *NmapScan) preScan() {
	s.Status = in_progress
}
func (s *NmapScan) postScan() {
	s.Status = finished
}

func (s *NmapScan) constructCmd(args string) string {
	return fmt.Sprintf("nmap %s %s -oA %s", args, s.Target, s.Outfile)
}

// Run nmap scan
func (s *NmapScan) RunNmap() {
	// Pre-scan checks
	s.preScan()

	// Run nmap
	utils.Config.Log.LogDebug(fmt.Sprintf("Nmap command: %s", s.Cmd))
	res, err := exec.Command("sh", "-c", s.Cmd).Output()
	if err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Failed to nmap destination %s (%s): %s", s.Target, s.Name, err))
		s.Status = failed
	}
	s.Result = res

	// Post-scan checks
	s.postScan()

}

// Parse nmap XML output file
func (s *NmapScan) ParseOutput() *go_nmap.NmapRun {
	sweepXML := fmt.Sprintf("%s.xml", s.Outfile)
	dat, err := ioutil.ReadFile(sweepXML)
	if err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Error while opening output file: %s", sweepXML))
		return nil
	}

	res, err := go_nmap.Parse(dat)
	if err != nil {
		utils.Config.Log.LogError("Error while parsing nmap output")
		return nil
	}
	return res
}

// ---------------------------------------------------------------------------------------
// SCAN MANAGEMENT
// ---------------------------------------------------------------------------------------
func ReportStatusNmap() {
	ticker := time.Tick(notificationDelay)
	for {
		<-ticker

		if len(ScansList) != 0 {
			i := 0
			for _, scan := range ScansList {
				switch {
				case scan.Status == null:
					break
				case scan.Status == failed:
					utils.Config.Log.LogError(fmt.Sprintf("Nmap failed on host: %s", scan.Target))
				case scan.Status == in_progress:
					utils.Config.Log.LogInfo(fmt.Sprintf("Nmap work in progress on host (%s):\t%s", scan.Name, scan.Target))
					// Update in place, remove finished scans
					ScansList[i] = scan
					i++
				case scan.Status == finished:
					utils.Config.Log.LogNotify(fmt.Sprintf("Nmap finished on host (%s):\t%s", scan.Name, scan.Target))
					utils.Config.Log.LogNotify(fmt.Sprintf("Output has been saved at (%s):\t%s", scan.Name, utils.Config.Outfolder))
				}
			}
			// Update in place, remove finished scans
			ScansList = ScansList[:i]
		}
	}
}
