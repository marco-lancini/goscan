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
    # Launch scan
    cmd = 'onesixtyone -c {wlist} {ip}'.format(wlist=c.WORDLIST_SNMP, ip=ip)
    results = subprocess.check_output(cmd, shell=True).strip()

    # Parse results
    if results != '':
        if "Windows" in results:
            res = results.split("Software: ")[1]
        elif "Linux" in results:
            res = results.split("[public] ")[1]
        else:
            res = results

        # Write results to file
        with open(output, 'ab') as fp:
            fp.write('%s' % res)
            fp.write('\n')



# ========================================================================================
# MAIN
def main():
    if len(sys.argv) < 2:
        c.bcolors.print_error('Usage: %s <IP> [port]' % sys.argv[0])
        sys.exit(0)

    # Parameters
    ip = sys.argv[1]
    port = None

    # Output file
    enum_type = 'snmp'
    script = 'onesixtyone'
    output = c.get_output_file(ip, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, ip))
    exec_scan(ip, port, output)


if __name__ == '__main__':
    main()
