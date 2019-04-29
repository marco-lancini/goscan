package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumHTTP() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)
			if port.Number == 80 || port.Number == 443 || port.Number == 8080 ||
				strings.Contains(strings.ToLower(service.Name), "http") ||
				strings.Contains(strings.ToLower(service.Name), "https") ||
				strings.Contains(strings.ToLower(service.Name), "ssl/http") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))
				protocol := "http"
				if strings.Contains(strings.ToLower(service.Name), "https") ||
					strings.Contains(strings.ToLower(service.Name), "ssl/http") {
					protocol = "https"
				}

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_http_%d_nmap", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-sitemap-generator,http-auth-finder,http-auth,http-fileupload-exploiter,http-put,http-sql-injection,http-stored-xss,http-xssed,http-php-version,http-unsafe-output-escaping,http-phpmyadmin-dir-traversal,http-ntlm-info,http-phpself-xss,http-open-redirect,http-iis-webdav-vuln,http-form-fuzzer,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-robots.txt,http-wordpress-brute,http-wordpress-enum --script-args http.useragent='Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Gecko/20100101 Firefox/15.0.1',http-put.url='/uploads/rootme.php',http-put.file='/root/www/php-reverse.php',basepath='/' -p%d", port.Number)
				s.runNmap(name, s.Target.Address, "HTTP", name, nmapArgs)

				// -----------------------------------------------------------------------
				// NIKTO
				// -----------------------------------------------------------------------
				output := s.makeOutputPath("HTTP", fmt.Sprintf("%s_http_%d_nikto", s.Target.Address, port.Number))
				cmd := fmt.Sprintf("nikto -host %s -p %d > %s", s.Target.Address, port.Number, output)
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// DIRB
				// -----------------------------------------------------------------------
				output = s.makeOutputPath("HTTP", fmt.Sprintf("%s_http_%d_dirb", s.Target.Address, port.Number))
				cmd = fmt.Sprintf("dirb %s://%s:%d -o %s -S -r", protocol, s.Target.Address, port.Number, output)
				s.runCmd(cmd)

				// -----------------------------------------------------------------------
				// SQLMAP - NON POLITE
				// -----------------------------------------------------------------------
				if s.Polite != "POLITE" {
					output := s.makeOutputPath("HTTP", fmt.Sprintf("%s_http_%d_sqlmap", s.Target.Address, port.Number))
					cmd := fmt.Sprintf("sqlmap -u %s://%s:%d --crawl=1 > %s", protocol, s.Target.Address, port.Number, output)
					s.runCmd(cmd)
				}

				// -----------------------------------------------------------------------
				// FIMAP - NON POLITE
				// -----------------------------------------------------------------------
				if s.Polite != "POLITE" {
					output = s.makeOutputPath("HTTP", fmt.Sprintf("%s_http_%d_fimap", s.Target.Address, port.Number))
					cmd = fmt.Sprintf("fimap -u \"%s://%s:%d\" > %s", protocol, s.Target.Address, port.Number, output)
					s.runCmd(cmd)
				}

			}
		}
	}
}
