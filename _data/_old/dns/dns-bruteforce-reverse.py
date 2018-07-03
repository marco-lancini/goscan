import os
import sys
import subprocess


# ========================================================================================
# HACK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import launch_scan as c


# ========================================================================================
# SCAN
def exec_scan(domain, output, base, lower, upper):
    hosts = []
    for ip in range(lower, upper+1):
        cmd = 'host %s.%s' % (base, ip)
        results = (subprocess.check_output(cmd, shell=True)).strip()

        if domain in results:
            tokens = results.split(" ")
            host = tokens[4]
            ip = tokens[0]
            out = '%s %s' % (host, ip)
            hosts.append(out)
            print out

    # Write results to file
    with open(output, 'ab') as fp:
        fp.write('\n'.join(hosts))
        fp.write('\n')



# ========================================================================================
# MAIN
def main():
    if len(sys.argv) < 2:
        c.bcolors.print_error('Usage: %s <target domain> <base ip> [lower] [upper]\nExample: megacorpone.com 38.100.193 200 202' % sys.argv[0])
        sys.exit(0)

    # Parameters
    domain = sys.argv[1]
    base = sys.argv[2]
    lower = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    upper = int(sys.argv[4]) if len(sys.argv) > 3 else 255

    # Output file
    enum_type = 'dns'
    script = 'bruteforce-reverse'
    output = c.get_output_file(ip, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, ip))
    exec_scan(domain, output, base, lower, upper)


if __name__ == '__main__':
    main()
