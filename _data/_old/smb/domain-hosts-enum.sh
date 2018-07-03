#!/bin/sh

echo "\n[+] Computer name"
grep -r "Computer name" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/

echo "\n[+] NetBIOS Computer name"
grep -r "NetBIOS computer name" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/

echo "\n[+] NetBIOS name"
grep -r "NetBIOS name" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | cut -d " " -f 1,3,4,5

echo "\n[+] NetBIOS MAC"
grep -r "NetBIOS MAC" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | cut -d " " -f 1,9,10,11

echo "\n[+] NetBIOS user"
grep -r "NetBIOS user" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/ | cut -d " " -f 1,6,7,8

echo "\n[+] Domain name"
grep -r "Domain name" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/

echo "\n[+] Forest name"
grep -r "Forest name" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/

echo "\n[+] FQDN"
grep -r "FQDN" --include="tcp-full.nmap" --exclude="vuln-scan.*" --color=always /root/assessment/

echo "\n[+] Summary"
find /root/assessment/ -type f -iname "enum4linux" | xargs winlanfoe.pl
