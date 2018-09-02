package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumSNMP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if port.Number == 161 || strings.Contains(strings.ToLower(service.Name), "snmp") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_snmp_%d_nmap", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=snmp-netstat,snmp-processes,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -p161,162,%d", port.Number)
				s.runNmap(name, s.Target.Address, "SNMP", name, nmapArgs)

				// -----------------------------------------------------------------------
				// SNMPCHECK
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("SNMP", fmt.Sprintf("%s_snmp_%d_snmpcheck", s.Target.Address, port.Number))
				cmd := fmt.Sprintf("snmpcheck %s > %s", s.Target.Address, output)
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// ONESIXTYONE
				// -----------------------------------------------------------------------
				output = s.makeOutputPath("SNMP", fmt.Sprintf("%s_snmp_%d_onesixtyone", s.Target.Address, port.Number))
				cmd = fmt.Sprintf("onesixtyone -c %s %s > %s", utils.WORDLIST_SNMP, s.Target.Address, output)
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// SNMPWALK
				// -----------------------------------------------------------------------
				output = s.makeOutputPath("SNMP", "snmp_snmpwalk_1")
				cmd = fmt.Sprintf("snmpwalk -c public -v1 %s 1 > %s", s.Target.Address, output)
				s.runCmd(cmd)

				output = s.makeOutputPath("SNMP", "snmp_snmpwalk_system-processes")
				cmd = fmt.Sprintf("snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.1.6.0 > %s", s.Target.Address, output)
				s.runCmd(cmd)

				output = s.makeOutputPath("SNMP", "snmp_snmpwalk_running-programs")
				cmd = fmt.Sprintf("snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.4.2.1.2 > %s", s.Target.Address, output)
				s.runCmd(cmd)

				output = s.makeOutputPath("SNMP", "snmp_snmpwalk_processes-path")
				cmd = fmt.Sprintf("snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.4.2.1.4 > %s", s.Target.Address, output)
				s.runCmd(cmd)

				output = s.makeOutputPath("SNMP", "snmp_snmpwalk_storage-units")
				cmd = fmt.Sprintf("snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.2.3.1.4 > %s", s.Target.Address, output)
				s.runCmd(cmd)

				output = s.makeOutputPath("SNMP", "snmp_snmpwalk_installed-software")
				cmd = fmt.Sprintf("snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.6.3.1.2 > %s", s.Target.Address, output)
				s.runCmd(cmd)

				output = s.makeOutputPath("SNMP", "snmp_snmpwalk_user-accounts")
				cmd = fmt.Sprintf("snmpwalk -c public -v1 %s 1.3.6.1.4.1.77.1.2.25 > %s", s.Target.Address, output)
				s.runCmd(cmd)

				output = s.makeOutputPath("SNMP", "snmp_snmpwalk_open-tcp-ports")
				cmd = fmt.Sprintf("snmpwalk -c public -v1 %s 1.3.6.1.2.1.6.13.1.3 > %s", s.Target.Address, output)
				s.runCmd(cmd)
			}
		}
	}
}
