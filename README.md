<p align="center"><img src="https://raw.githubusercontent.com/marco-lancini/goscan/master/.github/goscan_logo.png" width="40%"></p>


**GoScan** is an interactive network scanner client, featuring auto-completion, which provides abstraction and automation over nmap.

Although it started as a small side-project I developed in order to learn [@golang](https://twitter.com/golang), GoScan can now be used to perform host discovery, port scanning, and service enumeration not only in situations where being stealthy is not a priority and time is limited (think at CTFs, OSCP, exams, etc.), but also (with a few tweaks in its configuration) during professional engagements.

GoScan is also particularly suited for unstable environments (think unreliable network connectivity, lack of "`screen`", etc.), given that it fires scans and maintain their state in an SQLite database. Scans run in the background (detached from the main thread), so even if connection to the box running GoScan is lost, results can be uploaded asynchronously (more on this below). That is, data can be imported into GoScan at different stages of the process, without the need to restart the entire process from scratch if something goes wrong.

In addition, the Service Enumeration phase integrates a collection of other tools (e.g., `EyeWitness`, `Hydra`, `nikto`, etc.), each one tailored to target a specific service.

![demo](https://raw.githubusercontent.com/marco-lancini/goscan/master/.github/demo.gif)



# Installation

#### Binary installation (Recommended)

Binaries are available from the [Release](https://github.com/marco-lancini/goscan/releases) page.

```bash
# Linux (64bit)
$ wget https://github.com/marco-lancini/goscan/releases/download/v2.4/goscan_2.4_linux_amd64.zip
$ unzip goscan_2.4_linux_amd64.zip

# Linux (32bit)
$ wget https://github.com/marco-lancini/goscan/releases/download/v2.4/goscan_2.4_linux_386.zip
$ unzip goscan_2.4_linux_386.zip

# After that, place the executable in your PATH
$ chmod +x goscan
$ sudo mv ./goscan /usr/local/bin/goscan
```

#### Build from source

```bash
# Clone and spin up the project
$ git clone https://github.com/marco-lancini/goscan.git
$ cd goscan/
$ docker-compose up --build
$ docker-compose run cli /bin/bash

# Initialize DEP
root@cli:/go/src/github.com/marco-lancini/goscan $ make init
root@cli:/go/src/github.com/marco-lancini/goscan $ make setup

# Build
root@cli:/go/src/github.com/marco-lancini/goscan $ make build

# To create a multi-platform binary, use the cross command via make
root@cli:/go/src/github.com/marco-lancini/goscan $ make cross
```




# Usage

GoScan supports all the main steps of network enumeration:

![process](https://raw.githubusercontent.com/marco-lancini/goscan/master/.github/goscan_process.png)


| Step | Commands |
| ---- | ----------- |
| 1. **Load targets**   | <ul><li>Add a single target via the CLI (must be a valid CIDR): `load target SINGLE <IP/32>`</li><li>Upload multiple targets from a text file or folder: `load target MULTI <path-to-file>`</li></ul>|
| 2. **Host Discovery** | <ul><li>Perform a Ping Sweep: `sweep <TYPE> <TARGET>`</li><li>  Or load results from a previous discovery:<ul><li>Add a single alive host via the CLI (must be a /32): `load alive SINGLE <IP>`</li><li>Upload multiple alive hosts from a text file or folder: `load alive MULTI <path-to-file>`</li></ul></li></ul> |
| 3. **Port Scanning** | <ul><li>Perform a port scan: `portscan <TYPE> <TARGET>`</li><li>Or upload nmap results from XML files or folder: `load portscan <path-to-file>`</li></ul> |
| 4. **Service Enumeration** | <ul><li>Dry Run (only show commands, without performing them): `enumerate <TYPE> DRY <TARGET>`</li><li> Perform enumeration of detected services: `enumerate <TYPE> <POLITE/AGGRESSIVE> <TARGET>`</li></ul> |
| 5. **Special Scans** | <ul><li>*EyeWitness*<ul><li>Take screenshots of websites, RDP services, and open VNC servers (KALI ONLY): `special eyewitness`</li><li>`EyeWitness.py` needs to be in the system path</li></ul></li><li>*Extract (Windows) domain information from enumeration data*<ul><li>`special domain <users/hosts/servers>`</li></ul></li><li>*DNS*<ul><li>Enumerate DNS (nmap, dnsrecon, dnsenum): `special dns DISCOVERY <domain>`</li><li>Bruteforce DNS: `special dns BRUTEFORCE <domain>`</li><li>Reverse Bruteforce DNS: `special dns BRUTEFORCE_REVERSE <domain> <base_IP>`</li></ul></li> |
| **Utils** | <ul><li>Show results: `show <targets/hosts/ports>`</li><li>Automatically configure settings by loading a config file: `set config_file <PATH>`</li><li>Change the output folder (by default `~/goscan`): `set output_folder <PATH>`</li><li>Modify the default nmap switches: `set nmap_switches <SWEEP/TCP_FULL/TCP_STANDARD/TCP_VULN/UDP_STANDARD> <SWITCHES>`</li><li>Modify the default wordlists: `set_wordlists <FINGER_USER/FTP_USER/...> <PATH>`</li></ul> |



## External Integrations

The _Service Enumeration_ phase currently supports the following integrations:

| WHAT | INTEGRATION |
| ---- | ----------- |
| ARP  | <ul><li>nmap</li></ul> |
| DNS  | <ul><li>nmap</li><li>dnsrecon</li><li>dnsenum</li><li>host</li></ul> |
| FINGER  | <ul><li>nmap</li><li>finger-user-enum</li></ul> |
| FTP  | <ul><li>nmap</li><li>ftp-user-enum</li><li>hydra [AGGRESSIVE]</li></ul> |
| HTTP | <ul><li>nmap</li><li>nikto</li><li>dirb</li><li>EyeWitness</li><li>sqlmap [AGGRESSIVE]</li><li>fimap [AGGRESSIVE]</li></ul> |
| RDP  | <ul><li>nmap</li><li>EyeWitness</li></ul> |
| SMB  | <ul><li>nmap</li><li>enum4linux</li><li>nbtscan</li><li>samrdump</li></ul> |
| SMTP | <ul><li>nmap</li><li>smtp-user-enum</li></ul> |
| SNMP | <ul><li>nmap</li><li>snmpcheck</li><li>onesixtyone</li><li>snmpwalk</li></ul> |
| SSH  | <ul><li>hydra [AGGRESSIVE]</li></ul> |
| SQL  | <ul><li>nmap</li></ul> |
| VNC  | <ul><li>EyeWitness</li></ul> |




# License

GoScan is released under a MIT License. See the `LICENSE` file for full details.
