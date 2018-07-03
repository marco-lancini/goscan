import os
import sys
import subprocess


# ========================================================================================
# HACK
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import launch_scan as c


# ========================================================================================
# SCAN
def exec_scan(domain, output, wordlist):
    hosts = []
    with open(wordlist, 'rb') as fp:
        for name in fp.readlines():
            name = name.strip()
            cmd = 'host %s.%s' % (name, domain)
            results = (subprocess.check_output(cmd, shell=True)).strip()

            if "has address" in results:
                tokens = results.split(" ")
                host = tokens[0]
                ip = tokens[3]
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
        c.bcolors.print_error('Usage: %s <target domain> [wordlist]' % sys.argv[0])
        sys.exit(0)

    # Parameters
    domain = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else c.WORDLIST_DNS_BRUTEFORCE

    # Output file
    enum_type = 'dns'
    script = 'bruteforce-forward'
    output = c.get_output_file(domain, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, domain))
    exec_scan(domain, output, wordlist)


if __name__ == '__main__':
    main()
