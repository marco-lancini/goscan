# GoScan


**GoScan** is a project I developed in order to learn [@golang](https://twitter.com/golang). It is an interactive network scanner client, featuring auto-complete, which provides abstraction and automation over nmap.

It can be used to perform host discovery, port scanning, and service enumeration in situations where being stealthy is not a priority, and time is limited (think at CTFs, OSCP, exams, etc.).

[![asciicast](https://asciinema.org/a/4ebtOAiDKmM1X89yCIpFQjqSQ.png)](https://asciinema.org/a/4ebtOAiDKmM1X89yCIpFQjqSQ)



# Installation

#### Binary installation (Recommended)

Binaries are available from the [Release](https://github.com/marco-lancini/goscan/releases) page.

```bash
# macOS (darwin)
wget https://github.com/marco-lancini/goscan/releases/download/v1.0/goscan_1.0_darwin_amd64.zip
unzip goscan_1.0_darwin_amd64.zip

# Linux
wget https://github.com/marco-lancini/goscan/releases/download/v1.0/goscan_1.0_linux_amd64.zip
unzip goscan_1.0_linux_amd64.zip

# After that, place the executable in your PATH
chmod +x goscan
sudo mv ./goscan /usr/local/bin/goscan
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


#### Docker (development only)

```bash
$ git clone https://github.com/marco-lancini/goscan.git
$ cd goscan/
$ docker-compose up --build
```




# Usage

GoScan supports the 3 main steps of network enumeration:

1. Host Discovery (ARP + ping sweep): `sweep <TYPE> <TARGET>`
2. Port Scanning: `portscan <TYPE> <TARGET>`
3. Service Enumeration: `enumerate <TYPE> <POLITE/AGGRESSIVE> <TARGET>`

In addition, it has a couple of supporting commands

- Change output folder (by default `~/goscan`): `set_output_folder <PATH>`
- Show collected data: `show hosts`


#### External Integrations

The _Service Enumeration_ phase currently supports the following integrations:

| WHAT | INTEGRATION |
| ---- | ----------- |
| ARP  | <ul><li>nmap</li><li>netdiscover</li></ul> |
| DNS  | <ul><li>nmap</li></ul> |
| FINGER  | <ul><li>nmap</li><li>finger-user-enum</li></ul> |
| FTP  | <ul><li>nmap</li><li>ftp-user-enum</li><li>hydra</li></ul> |
| HTTP | <ul><li>nmap</li><li>nikto</li><li>dirb</li><li>sqlmap</li><li>fimap</li></ul> |
| RDP  | <ul><li>nmap</li></ul> |
| SMB  |  |
| SMTP  | <ul><li>nmap</li><li>smtp-user-enum</li></ul> |
| SNMP  | <ul><li>nmap</li><li>snmpcheck</li></ul> |
| SSH  | <ul><li>hydra</li></ul> |
| SQL  | <ul><li>nmap</li></ul> |




# Todo List

- [ ] Sweep: remove own IP
- [ ] PortScan: parse scripts output
- [ ] PortScan: dynamic nmap switches
- [ ] Enumeration: dynamic wordlists
- [ ] Enumeration: add services (dns, smb, snmp)
- [ ] Import/Export (nmap, custom)

# License

GoScan is released under a MIT License. See the `LICENSE` file for full details.
