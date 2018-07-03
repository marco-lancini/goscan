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
    cmd = 'python /usr/local/bin/samrdump.py %s %s/SMB' % (ip, port)
    res = subprocess.check_output(cmd, shell=True)

    # Parse results
    results = []
    if ('Connection refused' not in res) and ('Connect error' not in res) and ('Connection reset' not in res):
        lines = res.split('\n')
        for line in lines:
            if 'Found' in line or 'domain' in line or '. ' in line:
                temp = "[>] %s - SAMRDUMP User accounts/domains: %s" % (IP, line)
                results.append(temp)

    # Write results to file
    with open(output, 'ab') as fp:
        fp.write('\n'.join(results))
        fp.write('\n')



# ========================================================================================
# MAIN
def main():
    if len(sys.argv) < 2:
        c.bcolors.print_error('Usage: %s <IP> [port]' % sys.argv[0])
        sys.exit(0)

    # Parameters
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 445

    # Output file
    enum_type = 'smb'
    script = 'samrdump'
    output = c.get_output_file(ip, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, ip))
    exec_scan(ip, port, output)


if __name__ == '__main__':
    main()
