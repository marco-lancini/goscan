package scan

import (
	"fmt"
	"github.com/marco-lancini/goscan/core/utils"
)

// ---------------------------------------------------------------------------------------
// DISPATCHER
// ---------------------------------------------------------------------------------------
func GatherDomain(kind string) {
	// Dispatch scan
	switch kind {
	case "users":
		gatherUsers()
	case "hosts":
		gatherHosts()
	case "servers":
		gatherServers()
	default:
		utils.Config.Log.LogError("Invalid type of scan")
		return
	}
}

func gatherUsers() {
	utils.Config.Log.LogNotify("Users:")
	cmd := fmt.Sprintf(`grep -r "Account" --include="*enum4linux*" --color=always %s | awk '{print $8}'`, utils.Config.Outfolder)
	results, _ := utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("SIDs:")
	cmd = fmt.Sprintf(`grep -r "S-1" --include="*.nmap" --include="enum4linux" --exclude="vuln-scan.*" --color=always %s`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)
}

func gatherHosts() {
	utils.Config.Log.LogNotify("Computer name:")
	cmd := fmt.Sprintf(`grep -r "Computer name" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s`, utils.Config.Outfolder)
	results, _ := utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("NetBIOS Computer name:")
	cmd = fmt.Sprintf(`grep -r "NetBIOS computer name" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("NetBIOS name:")
	cmd = fmt.Sprintf(`grep -r "NetBIOS name" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | cut -d " " -f 1,3,4,5`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("NetBIOS MAC:")
	cmd = fmt.Sprintf(`grep -r "NetBIOS MAC" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | cut -d " " -f 1,9,10,11`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("NetBIOS user:")
	cmd = fmt.Sprintf(`grep -r "NetBIOS user" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | cut -d " " -f 1,6,7,8`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Domain name:")
	cmd = fmt.Sprintf(`grep -r "Domain name" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Forest name:")
	cmd = fmt.Sprintf(`grep -r "Forest name" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("FQDN:")
	cmd = fmt.Sprintf(`grep -r "FQDN" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Summary:")
	cmd = fmt.Sprintf(`find %s -type f -iname "enum4linux" | xargs winlanfoe.pl`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)
}

func gatherServers() {

	utils.Config.Log.LogNotify("Hostname:")
	cmd := fmt.Sprintf(`grep -riE "*<00>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<unique>"`, utils.Config.Outfolder)
	results, _ := utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Domain name:")
	cmd = fmt.Sprintf(`grep -riE "*<00>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<group>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Domain Master Browser:")
	cmd = fmt.Sprintf(`grep -riE "*<1B>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<unique>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Domain Controllers:")
	cmd = fmt.Sprintf(`grep -riE "*<1C>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<group>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Master Browser:")
	cmd = fmt.Sprintf(`grep -riE "*<1D>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<unique>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)
	cmd = fmt.Sprintf(`grep -riE "\x01\x02__MSBROWSE__\x02<01>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<group>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Messenger Service:")
	cmd = fmt.Sprintf(`grep -riE "*<01>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<unique>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)
	cmd = fmt.Sprintf(`grep -riE "*<03>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<unique>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Remote Access Service:")
	cmd = fmt.Sprintf(`grep -riE "*<06>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<unique>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("Browser Service Elections:")
	cmd = fmt.Sprintf(`grep -riE "*<1E>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<group>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("File Server Service:")
	cmd = fmt.Sprintf(`grep -riE "*<20>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<unique>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)

	utils.Config.Log.LogNotify("RAS Client Service:")
	cmd = fmt.Sprintf(`grep -riE "*<21>" --include="*.nmap" --exclude="vuln-scan.*" --color=always %s | grep "<unique>"`, utils.Config.Outfolder)
	results, _ = utils.ShellCmd(cmd)
	fmt.Printf(results)
}
