import os
import sys
import subprocess


# ========================================================================================
# HACK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import launch_scan as c


# ========================================================================================
# SCAN
def exec_scan(domain, dns, output):
    cmd = 'dnsenum --dnsserver {nameserver} --enum {domain} > {output}'.format(nameserver=dns, domain=domain, output=output)
    results = subprocess.check_output(cmd, shell=True)



# ========================================================================================
# MAIN
def main():
    if len(sys.argv) < 3:
        c.bcolors.print_error('Usage: %s <target domain> <dnsserver>' % sys.argv[0])
        sys.exit(0)

    # Parameters
    domain = sys.argv[1]
    dns = sys.argv[2]

    # Output file
    enum_type = 'dns'
    script = 'dnsenum'
    output = c.get_output_file(domain, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, domain))
    exec_scan(domain, dns, output)


if __name__ == '__main__':
    main()
