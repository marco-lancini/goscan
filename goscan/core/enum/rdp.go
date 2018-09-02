package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumRDP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if port.Number == 3389 || strings.Contains(strings.ToLower(service.Name), "ms-wbt-server") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_rdp_nmap_%d", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-sV --script=rdp-vuln-ms12-020 -p%d", port.Number)
				s.runNmap(name, s.Target.Address, "RDP", name, nmapArgs)
			}
		}
	}
}
