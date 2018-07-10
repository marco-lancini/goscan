package utils

import (
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/marco-lancini/goscan/core/model"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------------------
var Config config

var Const_notification_delay_unit = 10
var Const_example_target_cidr = "127.0.0.1/32"
var Const_example_target_desc = "Target CIDR or /32 for single target"

// NMAP COMMANDS
var Const_UDP_PORTS = "19,53,69,79,111,123,135,137,138,161,177,445,500,514,520,1434,1900,5353"
var Const_NMAP_SWEEP = "-n -sn -PE -PP"
var Const_NMAP_TCP_FULL = "-Pn -sT -sC -A -T4 -p-"
var Const_NMAP_TCP_STANDARD = "-Pn -sS -A -T4 --top-ports 200"
var Const_NMAP_TCP_VULN = "-Pn -sT -sV -p- --script=vulscan/vulscan.nse"
var Const_NMAP_UDP_STANDARD = fmt.Sprintf("-Pn -sU -sC -A -T4 -p%s", Const_UDP_PORTS)

// WORDLISTS
var WORDLIST_FUZZ_NAMELIST = "/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/names/namelist.txt"
var WORDLIST_MSF_PWDS = "/usr/share/wordlists/metasploit/unix_passwords.txt"
var WORDLIST_FINGER_USER = WORDLIST_FUZZ_NAMELIST
var WORDLIST_FTP_USER = WORDLIST_FUZZ_NAMELIST
var WORDLIST_SMTP = WORDLIST_FUZZ_NAMELIST
var WORDLIST_SNMP = "/usr/share/doc/onesixtyone/dict.txt"
var WORDLIST_DNS_BRUTEFORCE = WORDLIST_FUZZ_NAMELIST
var WORDLIST_HYDRA_SSH_USER = WORDLIST_FUZZ_NAMELIST
var WORDLIST_HYDRA_SSH_PWD = WORDLIST_MSF_PWDS
var WORDLIST_HYDRA_FTP_USER = WORDLIST_FUZZ_NAMELIST
var WORDLIST_HYDRA_FTP_PWD = WORDLIST_MSF_PWDS

// ---------------------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------------------
type config struct {
	Outfolder string
	Target    string
	Log       *Logger
	DB        *gorm.DB
}

// Initialize global config (db, logger, etc.)
// From now on it will be accessible as utils.Config
func InitConfig() {
	Config = config{}
	// Initialize logger
	Config.Log = InitLogger()
	// Setup Outfolder
	Config.Outfolder = filepath.Join(os.Getenv("OUT_FOLDER"), "goscan")
	EnsureDir(Config.Outfolder)
	// Init DB
	Config.DB = model.InitDB()
	Config.Log.LogDebug("Connected to DB")
}

// ---------------------------------------------------------------------------------------
// MANAGE COMMANDS
// ---------------------------------------------------------------------------------------
// Tokenize the command line
func ParseCmd(s string) (string, []string) {
	// Remove trailing spaces
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return "", make([]string, 0)
	}
	// Tokenize the string
	tokens := strings.Fields(s)
	// Get the command (1st word), and args
	cmd, args := tokens[0], tokens[1:]
	return cmd, args
}

// Extract the next argument from command line
func ParseNextArg(args []string) (string, []string) {
	if len(args) < 2 {
		return args[0], make([]string, 0)
	}
	return args[0], args[1:]
}

func ParseAllArgs(args []string) string {
	all_args := strings.Join(args, " ")
	return all_args
}

func ShellCmd(cmd string) string {
	Config.Log.LogDebug(fmt.Sprintf("Executing command: %s", cmd))
	output, err := exec.Command("sh", "-c", cmd).Output()

	if err != nil {
		Config.Log.LogError(fmt.Sprintf("Error while executing command: %s", err.Error()))
		return string(output)
	}

	return string(output)
}

// ---------------------------------------------------------------------------------------
// MANAGE FILES
// ---------------------------------------------------------------------------------------
// Ensures the program is run as root
func CheckSudo() {
	if os.Geteuid() != 0 {
		Config.Log.LogError("This program need to have root permission to execute nmap for now.")
		os.Exit(1)
	}
}

// Ensure the directory exists, or creeates it otherwise
func EnsureDir(dir string) {
	// Create a directory if doesn't exist
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, os.ModePerm)
		Config.Log.LogDebug(fmt.Sprintf("Created directory: %s", dir))
	}
}

// Replace slashes with underscores, when the string is used in a path
func CleanPath(s string) string {
	return strings.Replace(s, "/", "_", -1)

}

// Given a path and a list of strings, it writes them to file
func WriteArrayToFile(path string, s []string) {
	Config.Log.LogDebug(fmt.Sprintf("Writing output to file: %s", path))
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		Config.Log.LogError("Cannot create file")
	}
	defer f.Close()

	sep := "\n"
	for _, line := range s {
		if _, err = f.WriteString(line + sep); err != nil {
			Config.Log.LogError(fmt.Sprintf("Error while writing to file: %s", err))
		}
	}

}
