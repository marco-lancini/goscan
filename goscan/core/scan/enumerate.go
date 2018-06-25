package scan

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/utils"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------------------
// ENUMERATION
// ---------------------------------------------------------------------------------------
type EnumScan model.Enumeration

func NewEnumScan(target *model.Host, kind, polite string) *EnumScan {
	// Create a Scan
	s := &EnumScan{
		Target: target,
		Kind:   kind,
		Polite: polite,
		Status: not_started,
	}
	return s
}

func (s *EnumScan) preScan() {
	s.Status = in_progress
}
func (s *EnumScan) postScan() {
	s.Status = finished
}

func (s *EnumScan) makeOutputPath(folder, file string) string {
	resFolder := filepath.Join(utils.Config.Outfolder, utils.CleanPath(s.Target.Address), folder)
	resFile := filepath.Join(resFolder, file)
	utils.EnsureDir(resFolder)
	return resFile
}

func (s *EnumScan) runCmd(cmd string) ([]byte, error) {
	utils.Config.Log.LogDebug(fmt.Sprintf("Running: %s", cmd))
	res, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Failed Enumeration: %s", err))
		s.Status = failed
	}
	return res, err
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
// SCANNERS
// ---------------------------------------------------------------------------------------
func (s *EnumScan) EnumDNS() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "dns") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := "dns_nmap"
				nmapArgs := fmt.Sprintf("-sV -Pn -sU -p53,%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "FTP", name, nmapArgs)
				nmap.RunNmap()

				// POLITE
			}
		}
	}
}

func (s *EnumScan) EnumFINGER() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			if port.Number == 79 {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, "finger"))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("finger_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=finger -p%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "FINGER", name, nmapArgs)
				nmap.RunNmap()

				// -----------------------------------------------------------------------
				// FINGER-USER-ENUM
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("FINGER", "finger_user-enum")
				cmd := fmt.Sprintf("finger-user-enum.pl -U %s -t %s > %s", utils.WORDLIST_FINGER_USER, s.Target.Address, output)
				s.runCmd(cmd)
			}
		}
	}
}

func (s *EnumScan) EnumFTP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "ftp") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("ftp_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -p%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "FTP", name, nmapArgs)
				nmap.RunNmap()

				// -----------------------------------------------------------------------
				// FTP-USER-ENUM
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("FTP", "ftp_user-enum")
				cmd := fmt.Sprintf("ftp-user-enum.pl -U %s -t %s > %s", utils.WORDLIST_FTP_USER, s.Target.Address, output)
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// HYDRA
				// -----------------------------------------------------------------------
				// If not polite scan
				if s.Polite != "POLITE" {
					// Build command
					output := s.makeOutputPath("FTP", "ftp_hydra")
					cmd := fmt.Sprintf("hydra -L %s -P %s -f -o %s -u %s -s %d ftp",
						utils.WORDLIST_HYDRA_FTP_USER, utils.WORDLIST_HYDRA_FTP_PWD,
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

func (s *EnumScan) EnumHTTP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "http") ||
				strings.Contains(strings.ToLower(service.Name), "https") ||
				strings.Contains(strings.ToLower(service.Name), "ssl/http") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("http_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-sitemap-generator,http-auth-finder,http-auth,http-fileupload-exploiter,http-put,http-sql-injection,http-stored-xss,http-xssed,http-php-version,http-unsafe-output-escaping,http-phpmyadmin-dir-traversal,http-ntlm-info,http-phpself-xss,http-open-redirect,http-iis-webdav-vuln,http-form-fuzzer,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-robots.txt,http-wordpress-brute,http-wordpress-enum --script-args http-put.url='/uploads/rootme.php',http-put.file='/root/www/php-reverse.php',basepath='/' -p%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "HTTP", name, nmapArgs)
				nmap.RunNmap()

				// -----------------------------------------------------------------------
				// NIKTO
				// -----------------------------------------------------------------------
				// Build command
				output := s.makeOutputPath("HTTP", fmt.Sprintf("http_nikto_%d", port.Number))
				cmd := fmt.Sprintf("nikto -host %s -p %d > %s", s.Target.Address, port.Number, output)
				// Run command
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// DIRB
				// -----------------------------------------------------------------------
				// Build command
				output = s.makeOutputPath("HTTP", fmt.Sprintf("http_dirb_%d", port.Number))
				protocol := "https"
				if strings.Contains(strings.ToLower(service.Name), "http") {
					protocol = "http"
				}
				cmd = fmt.Sprintf("dirb %s://%s:%d -o %s -S -r", protocol, s.Target.Address, port.Number, output)
				// Run command
				s.runCmd(cmd)

				// If not polite scan
				if s.Polite != "POLITE" {
					// -------------------------------------------------------------------
					// SQLMAP
					// -------------------------------------------------------------------
					// Build command
					output := s.makeOutputPath("HTTP", fmt.Sprintf("http_sqlmap_%d", port.Number))
					protocol := "https"
					if strings.Contains(strings.ToLower(service.Name), "http") {
						protocol = "http"
					}
					cmd := fmt.Sprintf("sqlmap -u %s://%s:%d --crawl=1 > %s", protocol, s.Target.Address, port.Number, output)
					// Run command
					s.runCmd(cmd)

					// -------------------------------------------------------------------
					// FIMAP
					// -------------------------------------------------------------------
					// Build command
					output = s.makeOutputPath("HTTP", fmt.Sprintf("http_fimap_%d", port.Number))
					protocol = "https"
					if strings.Contains(strings.ToLower(service.Name), "http") {
						protocol = "http"
					}
					cmd = fmt.Sprintf("fimap -u \"%s://%s:%d\" > %s", protocol, s.Target.Address, port.Number, output)
					// Run command
					s.runCmd(cmd)
				}
			}
		}
	}
}

func (s *EnumScan) EnumRDP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "ms-wbt-server") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("rdp_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV --script=rdp-vuln-ms12-020 -p%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "RDP", name, nmapArgs)
				nmap.RunNmap()
			}
		}
	}
}

func (s *EnumScan) EnumSMB() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "smb") ||
				strings.Contains(strings.ToLower(service.Name), "microsoft-ds") ||
				strings.Contains(strings.ToLower(service.Name), "netbios") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// POLITE
			}
		}
	}
}

func (s *EnumScan) EnumSMTP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "smtp") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("smtp_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=smtp-enum-users,smtp-vuln* --script-args='smtp-vuln-cve2010-4344.exploit' -p25,465,587,%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "SMTP", name, nmapArgs)
				nmap.RunNmap()

				// -----------------------------------------------------------------------
				// SMTP-USER-ENUM
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("SMTP", "smtp_user-enum")
				cmd := fmt.Sprintf("smtp-user-enum -M VRFY -U %s -t %s > %s", utils.WORDLIST_SMTP, s.Target.Address, output)
				s.runCmd(cmd)

				// POLITE
			}
		}
	}
}

func (s *EnumScan) EnumSNMP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "snmp") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("snmp_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=snmp-netstat,snmp-processes,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -p161,162,%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "SNMP", name, nmapArgs)
				nmap.RunNmap()

				// -----------------------------------------------------------------------
				// SNMPCHECK
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("SNMP", "snmp_snmpcheck")
				cmd := fmt.Sprintf("snmpcheck %s > %s", s.Target.Address, output)
				s.runCmd(cmd)

				// POLITE
			}
		}
	}
}

func (s *EnumScan) EnumSSH() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "ssh") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))
				// If not polite scan
				if s.Polite != "POLITE" {
					// -------------------------------------------------------------------
					// HYDRA
					// -------------------------------------------------------------------
					// Build command
					output := s.makeOutputPath("SSH", "ssh_hydra")
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

func (s *EnumScan) EnumSQL() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if strings.Contains(strings.ToLower(service.Name), "ms-sql") {
				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))
				name := fmt.Sprintf("sql_mssql_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes,ms-sql-brute,ms-sql-dac,ms-sql-empty-password,ms-sql-hasdbaccess,ms-sql-query,ms-sql-tables,ms-sql-xp-cmdshell --script-args mssql.instance-port=%d,mssql.username=sa,mssql.password=sa,ms-sql-query.query='SELECT * FROM master..syslogins' -p%d", port.Number, port.Number)
				nmap := NewScan(name, s.Target.Address, "SQL", name, nmapArgs)
				nmap.RunNmap()

			} else if strings.Contains(strings.ToLower(service.Name), "mysql") {
				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))
				name := fmt.Sprintf("sql_mysql_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=mysql-brute,mysql-databases,mysql-empty-password,mysql-enum,mysql-info,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "SQL", name, nmapArgs)
				nmap.RunNmap()

			} else if strings.Contains(strings.ToLower(service.Name), "oracle") {
				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))
				name := fmt.Sprintf("sql_oracle_nmap_%d", port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=oracle-brute,oracle-enum-users,oracle-sid-brute --script-args oracle-brute.sid=ORCL -p%d", port.Number)
				nmap := NewScan(name, s.Target.Address, "SQL", name, nmapArgs)
				nmap.RunNmap()

			}
		}
	}
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
				case scan.Status == null:
					break
				case scan.Status == failed:
					utils.Config.Log.LogError(fmt.Sprintf("Enumeration failed on host: %s", scan.Target.Address))
				case scan.Status == in_progress:
					utils.Config.Log.LogInfo(fmt.Sprintf("Enumeration in progress on host (%s):\t%s", scan.Kind, scan.Target.Address))
					// Update in place, remove finished scans
					EnumList[i] = scan
					i++
				case scan.Status == finished:
					utils.Config.Log.LogNotify(fmt.Sprintf("Enumeration finished on host (%s):\t%s", scan.Kind, scan.Target.Address))
					utils.Config.Log.LogNotify(fmt.Sprintf("Output has been saved at (%s):\t%s", scan.Kind, utils.Config.Outfolder))
				}
			}
			// Update in place, remove finished scans
			EnumList = EnumList[:i]
		}
	}
}
