package enum

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"strings"
)

func (s *EnumScan) EnumSQL() {
	for _, port := range s.Target.GetPorts(utils.Config.DB) {
		// Enumerate only if port is open
		if port.Status == "open" {
			// Dispatch the correct scanner
			service := port.GetService(utils.Config.DB)

			// ---------------------------------------------------------------------------
			// MS-SQL
			// ---------------------------------------------------------------------------
			if port.Number == 1433 || port.Number == 1434 || port.Number == 2433 || strings.Contains(strings.ToLower(service.Name), "ms-sql") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_sql_mssql_nmap_%d", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes,ms-sql-brute,ms-sql-dac,ms-sql-empty-password,ms-sql-hasdbaccess,ms-sql-query,ms-sql-tables,ms-sql-xp-cmdshell --script-args mssql.instance-port=%d,mssql.username=sa,mssql.password=sa,ms-sql-query.query='SELECT * FROM master..syslogins' -p%d", port.Number, port.Number)
				s.runNmap(name, s.Target.Address, "SQL", name, nmapArgs)
			}

			// ---------------------------------------------------------------------------
			// MYSQL
			// ---------------------------------------------------------------------------
			if port.Number == 3306 || strings.Contains(strings.ToLower(service.Name), "mysql") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_sql_mysql_nmap_%d", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=mysql-brute,mysql-databases,mysql-empty-password,mysql-enum,mysql-info,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -p%d", port.Number)
				s.runNmap(name, s.Target.Address, "SQL", name, nmapArgs)
			}

			// ---------------------------------------------------------------------------
			// ORACLE
			// ---------------------------------------------------------------------------
			if port.Number == 1521 || port.Number == 1526 || port.Number == 1541 || strings.Contains(strings.ToLower(service.Name), "oracle") {
				// Start Enumerating
				utils.Config.Log.LogInfo(fmt.Sprintf("Starting Enumeration: %s:%d (%s)", s.Target.Address, port.Number, service.Name))

				// -----------------------------------------------------------------------
				// NMAP
				// -----------------------------------------------------------------------
				name := fmt.Sprintf("%s_sql_oracle_nmap_%d", s.Target.Address, port.Number)
				nmapArgs := fmt.Sprintf("-sV -Pn --script=oracle-brute,oracle-enum-users,oracle-sid-brute --script-args oracle-brute.sid=ORCL -p%d", port.Number)
				s.runNmap(name, s.Target.Address, "SQL", name, nmapArgs)
			}
		}
	}
}
