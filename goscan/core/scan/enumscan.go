package scan

import (
	"goscan/core/model"
	"goscan/core/utils"
)

// ---------------------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------------------
var EnumList = []*EnumScan{}

// ---------------------------------------------------------------------------------------
// SCAN LAUNCHER
// ---------------------------------------------------------------------------------------
func ScanEnumerate(target string, polite string, kind string) {
	for i := 0; i < len(utils.Config.Hosts); i++ {
		// Scan only if:
		//   - target is ALL
		//   - or if host is the selected one
		if target == "ALL" || target == utils.Config.Hosts[i].Address {
			go workerEnum(&utils.Config.Hosts[i], kind, polite)
		}
	}
}

// ---------------------------------------------------------------------------------------
// WORKER
// ---------------------------------------------------------------------------------------
func workerEnum(h *model.Host, kind string, polite string) {
	// Instantiate new EnumScan
	s := NewEnumScan(h, kind, polite)
	EnumList = append(EnumList, s)

	// Run the scan
	s.Run()

}
