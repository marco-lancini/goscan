package scan

import (
	"fmt"
	go_nmap "github.com/lair-framework/go-nmap"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/utils"
	"io/ioutil"
	"path/filepath"
	"time"
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
		Status: model.NOT_STARTED,
	}
	// Construct output path and create if it doesn't exist
	s.Outfolder = filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), folder)
	s.Outfile = filepath.Join(s.Outfolder, utils.CleanPath(file))
	utils.EnsureDir(s.Outfolder)
	// Construct command
	s.Cmd = s.constructCmd(nmapArgs)
	return s
}

func (s *NmapScan) preScan() {
	s.Status = model.IN_PROGRESS
}
func (s *NmapScan) postScan() {
	s.Status = model.FINISHED
}

func (s *NmapScan) constructCmd(args string) string {
	return fmt.Sprintf("nmap %s %s -oA %s", args, s.Target, s.Outfile)
}

// Run nmap scan
func (s *NmapScan) RunNmap() {
	// Pre-scan checks
	s.preScan()

	// Run nmap
	_, err := utils.ShellCmd(s.Cmd)
	if err != nil {
		s.Status = model.FAILED
	}

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

// Parse nmap XML output file (no nmap scan needed)
func ParseOutput(sweepXML string) *go_nmap.NmapRun {
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
				case scan.Status == model.NULL:
					break
				case scan.Status == model.FAILED:
					utils.Config.Log.LogError(fmt.Sprintf("Nmap failed on host: %s", scan.Target))
				case scan.Status == model.IN_PROGRESS:
					utils.Config.Log.LogInfo(fmt.Sprintf("[%s] Nmap work in progress on host:\t%s", scan.Name, scan.Target))
					// Update in place, remove finished scans
					ScansList[i] = scan
					i++
				case scan.Status == model.FINISHED:
					utils.Config.Log.LogNotify(fmt.Sprintf("[%s] Nmap finished on host:\t%s", scan.Name, scan.Target))
					utils.Config.Log.LogNotify(fmt.Sprintf("[%s] Output has been saved at:\t%s", scan.Name, utils.Config.Outfolder))
				}
			}
			// Update in place, remove finished scans
			ScansList = ScansList[:i]
		}
	}
}
