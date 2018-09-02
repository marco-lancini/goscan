package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/scan"
	"github.com/marco-lancini/goscan/core/utils"
	"path/filepath"
	"time"
)

// ---------------------------------------------------------------------------------------
// ENUMSCAN
// ---------------------------------------------------------------------------------------
var notificationDelay time.Duration = time.Duration(utils.Const_notification_delay_unit) * time.Second
type EnumScan model.Enumeration
var EnumList = []*EnumScan{}

func NewEnumScan(target *model.Host, kind, polite string) *EnumScan {
	// Create a Scan
	s := &EnumScan{
		Target: target,
		Kind:   kind,
		Polite: polite,
		Status: model.NOT_STARTED,
	}
	return s
}

func (s *EnumScan) preScan() {
	s.Status = model.IN_PROGRESS
}
func (s *EnumScan) postScan() {
	s.Status = model.FINISHED
}

func (s *EnumScan) makeOutputPath(folder, file string) string {
	resFolder := filepath.Join(utils.Config.Outfolder, utils.CleanPath(s.Target.Address), folder)
	resFile := filepath.Join(resFolder, file)
	utils.EnsureDir(resFolder)
	return resFile
}

func (s *EnumScan) runCmd(cmd string) (string, error) {
	// If it's a dry run, only show the command
	if s.Polite == "DRY" {
		utils.Config.Log.LogDebug(fmt.Sprintf("[DRY RUN] %s", cmd))
		return "", nil
	}
	// Otherwise execute the command
	res, err := utils.ShellCmd(cmd)
	if err != nil {
		s.Status = model.FAILED
	}
	return res, err
}

func (s *EnumScan) runNmap(name, target, folder, file, nmapArgs string) {
	// If it's a dry run, only show the command
	if s.Polite == "DRY" {
		outfolder := filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), folder)
		outfile := filepath.Join(outfolder, file)
		cmd := fmt.Sprintf("nmap %s %s -oA %s", nmapArgs, target, outfile)
		utils.Config.Log.LogDebug(fmt.Sprintf("To be run: %s", cmd))
		return
	}
	// Otherwise execute the command
	nmap := scan.NewScan(name, target, folder, file, nmapArgs)
	nmap.RunNmap()
}

func (s *EnumScan) Run() {
	// Pre-scan checks
	s.preScan()

	// Dispatch scan
	switch s.Kind {
	case "DNS":
		s.EnumDNS()
	case "FINGER":
		s.EnumFINGER()
	case "FTP":
		s.EnumFTP()
	case "HTTP":
		s.EnumHTTP()
	case "RDP":
		s.EnumRDP()
	case "SMB":
		s.EnumSMB()
	case "SMTP":
		s.EnumSMTP()
	case "SNMP":
		s.EnumSNMP()
	case "SQL":
		s.EnumSQL()
	case "SSH":
		s.EnumSSH()
	case "ALL":
		s.EnumDNS()
		s.EnumFINGER()
		s.EnumFTP()
		s.EnumHTTP()
		s.EnumRDP()
		s.EnumSMB()
		s.EnumSMTP()
		s.EnumSNMP()
		s.EnumSQL()
		s.EnumSSH()
	}

	// Post-scan checks
	s.postScan()
}

// ---------------------------------------------------------------------------------------
// SCAN LAUNCHER
// ---------------------------------------------------------------------------------------
func ScanEnumerate(kind, polite, target string) {
	utils.Config.Log.LogInfo("Starting service enumeration")
	hosts := model.GetAllHosts(utils.Config.DB)
	for _, h := range hosts {
		// Scan only if:
		//   - target is ALL
		//   - or if host is the selected one
		if target == "ALL" || target == h.Address {
			temp := h
			go workerEnum(&temp, kind, polite)
		}
	}
}

func workerEnum(h *model.Host, kind string, polite string) {
	// Instantiate new EnumScan
	s := NewEnumScan(h, kind, polite)
	EnumList = append(EnumList, s)

	// Run the scan
	s.Run()
}

// ---------------------------------------------------------------------------------------
// SCAN MANAGEMENT
// ---------------------------------------------------------------------------------------
func ReportStatusEnum() {
	ticker := time.Tick(notificationDelay)
	for {
		<-ticker

		if len(EnumList) != 0 {
			i := 0
			for _, scan := range EnumList {
				switch {
				case scan.Status == model.NULL:
					break
				case scan.Status == model.FAILED:
					utils.Config.Log.LogError(fmt.Sprintf("Enumeration failed on host: %s", scan.Target.Address))
				case scan.Status == model.IN_PROGRESS:
					utils.Config.Log.LogInfo(fmt.Sprintf("[%s] Enumeration in progress on host:\t%s", scan.Kind, scan.Target.Address))
					// Update in place, remove finished scans
					EnumList[i] = scan
					i++
				case scan.Status == model.FINISHED:
					utils.Config.Log.LogNotify(fmt.Sprintf("[%s] Enumeration finished on host:\t%s", scan.Kind, scan.Target.Address))
					utils.Config.Log.LogNotify(fmt.Sprintf("[%s] Output has been saved at:\t%s", scan.Kind, utils.Config.Outfolder))
				}
			}
			// Update in place, remove finished scans
			EnumList = EnumList[:i]
		}
	}
}
