#!/bin/sh

echo "\n[+] Hostname"
grep -riE "*<00>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<unique>"

echo "\n[+] Domain name"
grep -riE "*<00>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<group>"

echo "\n[+] Domain Master Browser"
grep -riE "*<1B>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<unique>"

echo "\n[+] Domain Controllers"
grep -riE "*<1C>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<group>"

echo "\n[+] Master Browser"
grep -riE "*<1D>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<unique>"
grep -riE "\x01\x02__MSBROWSE__\x02<01>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<group>"

echo "\n---------------------------\n"

echo "\n[+] Messenger Service"
grep -riE "*<01>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<unique>"
grep -riE "*<03>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<unique>"

echo "\n[+] Remote Access Service"
grep -riE "*<06>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<unique>"

echo "\n[+] Browser Service Elections"
grep -riE "*<1E>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<group>"

echo "\n[+] File Server Service"
grep -riE "*<20>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<unique>"

echo "\n[+] RAS Client Service"
grep -riE "*<21>" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | grep "<unique>"
