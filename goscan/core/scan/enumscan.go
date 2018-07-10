package scan

import (
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/utils"
)

// ---------------------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------------------
var EnumList = []*EnumScan{}

// ---------------------------------------------------------------------------------------
// SCAN LAUNCHER
// ---------------------------------------------------------------------------------------
func ScanEnumerate(target string, polite string, kind string) {
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
