#!/bin/sh

#echo "\n[+] Users"
grep -r "Account" --include="*enum4linux*" --color=always /root/assessment/ | awk '{print $8}'