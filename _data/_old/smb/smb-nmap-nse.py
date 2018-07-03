import os
import sys
import subprocess


# ========================================================================================
# HACK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import launch_scan as c


# ========================================================================================
# SCAN
def exec_scan(ip, port, output):
    cmd = 'nmap -v -p 137,138,139,445{port} --script=smb-os-discovery,smb-security-mode,smb-psexec,smb-mbenum,smb-enum-shares,smb-enum-sessions,smb-enum-processes,samba-vuln-cve-2012-1182,smb-check-vulns,nbtstat  --script-args=unsafe=1 -oA {name} {ip}'.format(port=port, name=output, ip=ip)
    results = subprocess.check_output(cmd, shell=True)

    name = '%s-enum-users' % output
    cmd = 'nmap -v -p 137,138,139,445{port} --script=smb-enum-users -sS -A -oA {name} {ip}'.format(port=port, name=name, ip=ip)
    results = subprocess.check_output(cmd, shell=True)

    name = '%s-nbtstat' % output
    cmd = 'sudo nmap -sU --script nbstat.nse -p137 -oA {name} {ip}'.format(name=name, ip=ip)



# ========================================================================================
# MAIN
def main():
    if len(sys.argv) < 2:
        c.bcolors.print_error('Usage: %s <IP> [port]' % sys.argv[0])
        sys.exit(0)

    # Parameters
    ip = sys.argv[1]
    if len(sys.argv) > 2:
        temp = str(sys.argv[2])
        if temp != '139' and temp != '445':
            port = ',%s' % temp
        else:
            port = ''
    else:
        port = ''

    # Output file
    enum_type = 'smb'
    script = 'nmap-nse-%s' % port
    output = c.get_output_file(ip, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, ip))
    exec_scan(ip, port, output)


if __name__ == '__main__':
    main()
