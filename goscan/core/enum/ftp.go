package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumFTP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if port.Number == 20 || port.Number == 21 || strings.Contains(strings.ToLower(service.Name), "ms-wbt-server") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_ftp_nmap_%d", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -p%d", port.Number)
				s.runNmap(name, s.Target.Address, "FTP", name, nmapArgs)

				// -----------------------------------------------------------------------
				// FTP-USER-ENUM
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("FTP", fmt.Sprintf("%s_ftp_user-enum", s.Target.Address))
				cmd := fmt.Sprintf("ftp-user-enum.pl -U %s -t %s > %s", utils.WORDLIST_FTP_USER, s.Target.Address, output)
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// HYDRA - NON POLITE
				// -----------------------------------------------------------------------
				if s.Polite != "POLITE" {
					output := s.makeOutputPath("FTP", fmt.Sprintf("%s_ftp_hydra", s.Target.Address))
					cmd := fmt.Sprintf("hydra -L %s -P %s -f -o %s -u %s -s %d ftp",
						utils.WORDLIST_HYDRA_FTP_USER, utils.WORDLIST_HYDRA_FTP_PWD,
						output,
						s.Target.Address, port.Number,
					)
					s.runCmd(cmd)
				}
			}
		}
	}
}
