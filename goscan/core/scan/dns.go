package scan

import (
	"bufio"
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------------------
// DISPATCHER
// ---------------------------------------------------------------------------------------
func ScanDNS(target string, kind string, baseIP string) {
	// Dispatch scan
	switch kind {
	case "DISCOVERY":
		DNSDiscovery(target)
	case "BRUTEFORCE":
		DNSBruteforce(target)
	case "BRUTEFORCE_REVERSE":
		DNSBruteforceReverse(target, baseIP)
	default:
		utils.Config.Log.LogError("Invalid type of scan")
		return
	}
}

// ---------------------------------------------------------------------------------------
// SCANS
// ---------------------------------------------------------------------------------------
func DNSDiscovery(target string) {
	utils.Config.Log.LogNotify("Starting DNS Discovery...")

	// -----------------------------------------------------------------------------------
	// NMAP
	// -----------------------------------------------------------------------------------
	utils.Config.Log.LogInfo("Running nmap...")
	nmapArgs := fmt.Sprintf("-sV -Pn -sU -p53")
	nmap := NewScan("dns_nmap", target, "", "dns_nmap", nmapArgs)
	nmap.RunNmap()

	// -----------------------------------------------------------------------------------
	// DNSRECON
	// -----------------------------------------------------------------------------------
	utils.Config.Log.LogInfo("Running dnsrecon...")
	outfile := filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), "dns_dnsrecon")
	cmd := fmt.Sprintf("dnsrecon -d %s > %s", target, outfile)
	utils.ShellCmd(cmd)

	outfile = filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), "dns_dnsrecon_axfr")
	cmd = fmt.Sprintf("dnsrecon -d %s -t axfr > %s", target, outfile)
	utils.ShellCmd(cmd)

	// -----------------------------------------------------------------------------------
	// DNSENUM
	// -----------------------------------------------------------------------------------
	utils.Config.Log.LogInfo("Running dnsenum...")
	outfile = filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), "dns_dnsenum")
	cmd = fmt.Sprintf("dnsenum --enum %s > %s", target, outfile)
	utils.ShellCmd(cmd)

	utils.Config.Log.LogNotify("DNS Discovery Completed")
}

func DNSBruteforce(target string) {
	utils.Config.Log.LogNotify("Starting DNS Bruteforce...")

	// -----------------------------------------------------------------------------------
	// READ SOURCE FILE
	// -----------------------------------------------------------------------------------
	wordlistFile, _ := os.Open(utils.WORDLIST_DNS_BRUTEFORCE)
	defer wordlistFile.Close()
	scanner := bufio.NewScanner(wordlistFile)
	scanner.Split(bufio.ScanLines)

	// -----------------------------------------------------------------------------------
	// QUERY HOST
	// -----------------------------------------------------------------------------------
	hosts := []string{}
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		cmd := fmt.Sprintf("host %s.%s", name, target)

		results, _ := utils.ShellCmd(cmd)
		records := strings.Split(results, "\n")
		for _, line := range records {
			if strings.Contains(line, "has address") {
				tokens := strings.Split(line, " ")
				host, ip := tokens[0], tokens[3]
				out := fmt.Sprintf("%s %s", host, ip)
				hosts = append(hosts, out)
				utils.Config.Log.LogNotify(out)
			}
		}
	}

	// -----------------------------------------------------------------------------------
	// SAVE RESULTS TO FILE
	// -----------------------------------------------------------------------------------
	outfile := filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), "dns_bruteforce_forward")
	utils.WriteArrayToFile(outfile, hosts)

	utils.Config.Log.LogNotify("DNS Bruteforce Completed")
}

func DNSBruteforceReverse(target string, baseIP string) {
	utils.Config.Log.LogNotify("Starting Reverse DNS Bruteforce...")
	lower, upper := 0, 255
	hosts := []string{}
	tokens := strings.Split(baseIP, ".")
	prefix := strings.Join(tokens[:3], ".")

	// -----------------------------------------------------------------------------------
	// QUERY HOST
	// -----------------------------------------------------------------------------------
	for i := lower; i <= upper; i++ {
		ip := fmt.Sprintf("%s.%d", prefix, i)
		cmd := fmt.Sprintf("host %s", ip)
		results, _ := utils.ShellCmd(cmd)
		records := strings.Split(results, "\n")

		for _, line := range records {
			if strings.Contains(line, target) {
				tokens := strings.Split(line, " ")
				ip, host := tokens[0], tokens[4]
				out := fmt.Sprintf("%s %s", host, ip)
				hosts = append(hosts, out)
				utils.Config.Log.LogNotify(out)
			}
		}
	}

	// -----------------------------------------------------------------------------------
	// SAVE RESULTS TO FILE
	// -----------------------------------------------------------------------------------
	outfile := filepath.Join(utils.Config.Outfolder, utils.CleanPath(target), "dns_bruteforce_reverse")
	utils.WriteArrayToFile(outfile, hosts)

	utils.Config.Log.LogNotify("DNS Reverse Bruteforce Completed")
}
