package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumSMTP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if port.Number == 25 || strings.Contains(strings.ToLower(service.Name), "smtp") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_smtp_%d_nmap", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=smtp-enum-users,smtp-vuln* --script-args='smtp-vuln-cve2010-4344.exploit' -p25,465,587,%d", port.Number)
				s.runNmap(name, s.Target.Address, "RDP", name, nmapArgs)

				// -----------------------------------------------------------------------
				// SMTP-USER-ENUM
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("SMTP", fmt.Sprintf("%s_smtp_%d_user-enum", s.Target.Address, port.Number))
				cmd := fmt.Sprintf("smtp-user-enum -M VRFY -U %s -t %s > %s", utils.WORDLIST_SMTP, s.Target.Address, output)
				s.runCmd(cmd)
			}
		}
	}
}
