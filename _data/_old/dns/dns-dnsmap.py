import os
import sys
import subprocess


# ========================================================================================
# HACK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import launch_scan as c


# ========================================================================================
# SCAN
def exec_scan(domain, output):
    cmd = 'dnsmap %s > %s' % (domain, output)
    results = subprocess.check_output(cmd, shell=True)



# ========================================================================================
# MAIN
def main():
    if len(sys.argv) < 2:
        c.bcolors.print_error('Usage: %s <target domain>' % sys.argv[0])
        sys.exit(0)

    # Parameters
    domain = sys.argv[1]

    # Output file
    enum_type = 'dns'
    script = 'dnsmap'
    output = c.get_output_file(domain, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, domain))
    exec_scan(domain, output)


if __name__ == '__main__':
    main()
