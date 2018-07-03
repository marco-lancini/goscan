#!/bin/sh

echo "\n[+] SIDs"
grep -r "S-1" --include="*.nmap" --include="enum4linux" --exclude="vuln-scan.*" --color=always /root/assessment/
