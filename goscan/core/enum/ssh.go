package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumSSH() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if port.Number == 22 || port.Number == 2222 || strings.Contains(strings.ToLower(service.Name), "ssh") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// HYDRA - NON POLITE
				// -----------------------------------------------------------------------
				if s.Polite != "POLITE" {
					// Build command
					output := s.makeOutputPath("SSH", fmt.Sprintf("%s_ssh_hydra", s.Target.Address))
					cmd := fmt.Sprintf("hydra -L %s -P %s -f -o %s -u %s -s %d ssh",
						utils.WORDLIST_HYDRA_SSH_USER, utils.WORDLIST_HYDRA_SSH_PWD,
						output,
						s.Target.Address, port.Number,
					)
					// Run command
					s.runCmd(cmd)
				}
			}
		}
	}
}
