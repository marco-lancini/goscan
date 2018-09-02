package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumDNS() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if port.Number == 53 || strings.Contains(strings.ToLower(service.Name), "dns") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_dns_nmap", s.Target.Address)
				nmapArgs := fmt.Sprintf("-sV -Pn -sU -p53,%d", port.Number)
				s.runNmap(name, s.Target.Address, "DNS", name, nmapArgs)
			}
		}
	}
}
