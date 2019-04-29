package utils

import (
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/marco-lancini/goscan/core/model"
	"os"
	"os/exec"
	"os/user"
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
var Const_NMAP_TCP_FULL = "--randomize-hosts -Pn -sS -sC -A -T4 -g53 -p-"
var Const_NMAP_TCP_STANDARD = "--randomize-hosts -Pn -sS -A -T4 -g53 --top-ports 1000"
var Const_NMAP_TCP_PROD = "--randomize-hosts -Pn -sT -sV -T3 -p-"
var Const_NMAP_TCP_VULN = "--randomize-hosts -Pn -sT -sV -p- --script=vulscan/vulscan.nse"
var Const_NMAP_UDP_STANDARD = fmt.Sprintf("--randomize-hosts -Pn -sU -sC -A -T4 -p%s", Const_UDP_PORTS)
var Const_NMAP_UDP_PROD = fmt.Sprintf("--randomize-hosts -Pn -sU -sC -sV -T3 -p%s", Const_UDP_PORTS)

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
	Log       *Logger
	DB        *gorm.DB
	DBPath    string
}

// Initialize global config (db, logger, etc.)
// From now on it will be accessible as utils.Config
func InitConfig() {
	Config = config{}
	
	// Initialize logger
	Config.Log = InitLogger()

	// Create output folder
	if os.Getenv("OUT_FOLDER") != "" {
		Config.Outfolder = filepath.Join(os.Getenv("OUT_FOLDER"), "goscan")
	} else {
		usr, _ := user.Current()
		Config.Outfolder = filepath.Join(usr.HomeDir, ".goscan")
	}
	EnsureDir(Config.Outfolder)

	// Init DB
	if os.Getenv("GOSCAN_DB_PATH") != "" {
		Config.DBPath = os.Getenv("GOSCAN_DB_PATH")
	} else {
		Config.DBPath = filepath.Join(Config.Outfolder, "goscan.db")
	}
	Config.DB = model.InitDB(Config.DBPath)
	Config.Log.LogDebug("Connected to DB")
}

// Change output folder as instructed by the user and re-init the db
func ChangeOutFolder(path string) {
	// Create the folder
	Config.Outfolder = path
	EnsureDir(Config.Outfolder)

	// Reinit the DB
	Config.DBPath = filepath.Join(Config.Outfolder, "goscan.db")
	Config.DB = model.InitDB(Config.DBPath)
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

// Parse all remaining arguments from command line
func ParseAllArgs(args []string) string {
	return strings.Join(args, " ")
}

func ShellCmd(cmd string) (string, error) {
	Config.Log.LogDebug(fmt.Sprintf("Executing command: %s", cmd))
	output, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		if !strings.Contains(err.Error(), "exit status 1") {
			Config.Log.LogError(fmt.Sprintf("Error while executing command: %s", err.Error()))
		}
		return string(output), err
	}
	return string(output), err
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

// Ensure the directory exists, or creates it otherwise
func EnsureDir(dir string) {
	// Create a directory if doesn't exist
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, os.ModePerm)
		Config.Log.LogDebug(fmt.Sprintf("Created directory: %s", dir))
	}
}

// Delete the specified directory
func RemoveDir(dir string) {
	os.RemoveAll(dir)
	Config.Log.LogDebug(fmt.Sprintf("Deleted directory: %s", dir))
}

// Replace slashes with underscores, when the string is used in a path
func CleanPath(s string) string {
	return strings.Replace(s, "/", "_", -1)
}

// Given a path and a list of strings, writes them to file
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
