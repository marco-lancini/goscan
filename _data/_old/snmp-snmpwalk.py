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
    # General
    name = '%s-1' % output
    cmd = 'snmpwalk -c public -v1 %s 1 > %s' % (ip, name)
    results = subprocess.check_output(cmd, shell=True).strip()

    # System Processes
    name = '%s-system-processes' % output
    cmd = 'snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.1.6.0 > %s' % (ip, name)
    results = subprocess.check_output(cmd, shell=True).strip()

    # Running programs
    name = '%s-running-programs' % output
    cmd = 'snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.4.2.1.2 > %s' % (ip, name)
    results = subprocess.check_output(cmd, shell=True).strip()

    # Processes path
    name = '%s-processes-path' % output
    cmd = 'snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.4.2.1.4 > %s' % (ip, name)
    results = subprocess.check_output(cmd, shell=True).strip()

    # Storage units
    name = '%s-storage-units' % output
    cmd = 'snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.2.3.1.4 > %s' % (ip, name)
    results = subprocess.check_output(cmd, shell=True).strip()

    # Installed software
    name = '%s-installed software' % output
    cmd = 'snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.6.3.1.2 > %s' % (ip, name)
    results = subprocess.check_output(cmd, shell=True).strip()

    # User accounts
    name = '%s-user-accounts' % output
    cmd = 'snmpwalk -c public -v1 %s 1.3.6.1.4.1.77.1.2.25 > %s' % (ip, name)
    results = subprocess.check_output(cmd, shell=True).strip()

    # Open TCP local ports
    name = '%s-open-tcp-ports' % output
    cmd = 'snmpwalk -c public -v1 %s 1.3.6.1.2.1.6.13.1.3 > %s' % (ip, name)
    results = subprocess.check_output(cmd, shell=True).strip()



# ========================================================================================
# MAIN
def main():
    if len(sys.argv) < 2:
        c.bcolors.print_error('Usage: %s <IP>' % sys.argv[0])
        sys.exit(0)

    # Parameters
    ip = sys.argv[1]
    port = None

    # Output file
    enum_type = 'snmp'
    script = 'snmpwalk'
    output = c.get_output_file(ip, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, ip))
    exec_scan(ip, port, output)


if __name__ == '__main__':
    main()
