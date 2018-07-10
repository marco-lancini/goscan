# GoScan


**GoScan** is a project I developed in order to learn [@golang](https://twitter.com/golang). It is an interactive network scanner client, featuring auto-complete, which provides abstraction and automation over nmap.

It can be used to perform host discovery, port scanning, and service enumeration in situations where being stealthy is not a priority, and time is limited (think at CTFs, OSCP, exams, etc.).

![demo](https://raw.githubusercontent.com/marco-lancini/goscan/master/.github/demo.gif)




# Installation

#### Binary installation (Recommended)

Binaries are available from the [Release](https://github.com/marco-lancini/goscan/releases) page.

```bash
# macOS (darwin)
$ wget https://github.com/marco-lancini/goscan/releases/download/v1.4/goscan_1.4_darwin_amd64.zip
$ unzip goscan_1.4_darwin_amd64.zip

# Linux
$ wget https://github.com/marco-lancini/goscan/releases/download/v1.4/goscan_1.4_linux_amd64.zip
$ unzip goscan_1.4_linux_amd64.zip

# After that, place the executable in your PATH
$ chmod +x goscan
$ sudo mv ./goscan /usr/local/bin/goscan
```

#### Build from source

```bash
$ git clone https://github.com/marco-lancini/goscan.git
$ cd goscan/goscan/
$ make setup
$ make build
```

To create a multi-platform binary, use the cross command via make:

```bash
$ make cross
```


#### Docker

```bash
$ git clone https://github.com/marco-lancini/goscan.git
$ cd goscan/
$ docker-compose up --build
```




# Usage

GoScan supports all the main steps of network enumeration:

1. Host Discovery (ARP + ping sweep): `sweep <TYPE> <TARGET>`
2. Port Scanning: `portscan <TYPE> <TARGET>`
3. Service Enumeration: `enumerate <TYPE> <POLITE/AGGRESSIVE> <TARGET>`

Plus some more:

4. DNS enumeration: `dns <DISCOVERY/BRUTEFORCE/BRUTEFORCE_REVERSE> <DOMAIN> [<BASE_IP>]`
5. Domain enumeration (Extract windows domain information from enumeration data): `domain <users/hosts/servers>`


In addition, it has a few supporting commands:

- Change the output folder (by default `~/goscan`): `set_output_folder <PATH>`
- Modify the default nmap switches: `set_nmap_switches <SWEEP/TCP_FULL/TCP_STANDARD/TCP_VULN/UDP_STANDARD>`
- Modify the default wordlists: `set_wordlists <FINGER_USER/FTP_USER/...>`
- Show live hosts: `show hosts`
- Show detailed ports information: `show ports`
- Reset the database: `db reset`



## Full Command List

| COMMAND |  SYNTAX  |
| ------- | -------- |
| Set output folder                    | `set_output_folder <PATH>` |
| Modify the default nmap switches     | `set_nmap_switches <SWEEP/TCP_FULL/TCP_STANDARD/TCP_VULN/UDP_STANDARD>` |
| Modify the default wordlists         | `set_wordlists <FINGER_USER/FTP_USER/...>` |
| Ping Sweep                           | `sweep <TYPE> <TARGET>` |
| Port Scan                            | `portscan <TYPE> <TARGET>` |
| Service Enumeration                  | `enumerate <TYPE> <POLITE/AGGRESSIVE> <TARGET>` |
| DNS Enumeration                      | `dns <DISCOVERY/BRUTEFORCE/BRUTEFORCE_REVERSE> <DOMAIN> [<BASE_IP>]` |
| Extract (windows) domain information from enumeration data | `domain <users/hosts/servers>` |
| Show live hosts                      | `show hosts` |
| Show detailed ports information      | `show ports` |
| Manage DB                            | `db <reset>` |
| Exit this program                    | `exit` |



## External Integrations

The _Service Enumeration_ phase currently supports the following integrations:

| WHAT | INTEGRATION |
| ---- | ----------- |
| ARP  | <ul><li>nmap</li><li>netdiscover</li></ul> |
| DNS  | <ul><li>nmap</li><li>dnsrecon</li><li>dnsenum</li><li>host</li></ul> |
| FINGER  | <ul><li>nmap</li><li>finger-user-enum</li></ul> |
| FTP  | <ul><li>nmap</li><li>ftp-user-enum</li><li>hydra</li></ul> |
| HTTP | <ul><li>nmap</li><li>nikto</li><li>dirb</li><li>sqlmap</li><li>fimap</li></ul> |
| RDP  | <ul><li>nmap</li></ul> |
| SMB  | <ul><li>nmap</li><li>enum4linux</li><li>nbtscan</li><li>samrdump</li></ul> |
| SMTP | <ul><li>nmap</li><li>smtp-user-enum</li></ul> |
| SNMP | <ul><li>nmap</li><li>snmpcheck</li><li>onesixtyone</li><li>snmpwalk</li></ul> |
| SSH  | <ul><li>hydra</li></ul> |
| SQL  | <ul><li>nmap</li></ul> |


# License

GoScan is released under a MIT License. See the `LICENSE` file for full details.
