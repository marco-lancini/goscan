package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumSMB() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if port.Number == 139 || port.Number == 445 ||
				strings.Contains(strings.ToLower(service.Name), "smb") ||
				strings.Contains(strings.ToLower(service.Name), "microsoft-ds") ||
				strings.Contains(strings.ToLower(service.Name), "netbios") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_smb_%d_nmap", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-v -p 137,138,139,445%d --script=smb-os-discovery,smb-security-mode,smb-psexec,smb-mbenum,smb-enum-shares,smb-enum-sessions,smb-enum-processes,samba-vuln-cve-2012-1182,smb-check-vulns,nbtstat  --script-args=unsafe=1", port.Number)
				s.runNmap(name, s.Target.Address, "SMB", name, nmapArgs)

				name = fmt.Sprintf("%s_smb_%d_nmap_enum-users", s.Target.Address, port.Number)
				nmapArgs = fmt.Sprintf("-v -p 137,138,139,445%d --script=smb-enum-users -sS -A", port.Number)
				s.runNmap(name, s.Target.Address, "SMB", name, nmapArgs)

				name = fmt.Sprintf("%s_smb_%d_nmap_nbtstat", s.Target.Address, port.Number)
				nmapArgs = fmt.Sprintf("-v -p 137,138,139,445%d -sU --script nbstat.nse", port.Number)
				s.runNmap(name, s.Target.Address, "SMB", name, nmapArgs)

				// -----------------------------------------------------------------------
				// ENUM4LINUX
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("SMB", fmt.Sprintf("%s_enum4linux", s.Target.Address))
				cmd := fmt.Sprintf("enum4linux -a %s > %s", s.Target.Address, output)
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// NBTSCAN
				// -----------------------------------------------------------------------
				output = s.makeOutputPath("SMB", fmt.Sprintf("%s_nbtscan", s.Target.Address))
				cmd = fmt.Sprintf("nbtscan -r %s > %s", s.Target.Address, output)
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// SAMRDUMP
				// -----------------------------------------------------------------------
				output = s.makeOutputPath("SMB", fmt.Sprintf("%s_samrdump", s.Target.Address))
				cmd = fmt.Sprintf("python /usr/local/bin/samrdump.py %s 445/SMB > %s", s.Target.Address, output)
				s.runCmd(cmd)
			}
		}
	}
}
