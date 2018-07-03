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
    cmd = 'nbtscan -r {ip} > {name}'.format(ip=ip, name=output)
    results = subprocess.check_output(cmd, shell=True)



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
    enum_type = 'smb'
    script = 'nbtscan'
    output = c.get_output_file(ip, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, ip))
    exec_scan(ip, port, output)


if __name__ == '__main__':
    main()
