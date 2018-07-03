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
    def check_connect():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connect = s.connect((ip, port))
            return True
        except:
            return False

    def try_vrfy(name):
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to server
        try:
            connect = s.connect((ip, port))
        except:
            return

        # Receive the banner
        banner = s.recv(1024)

        # Send HELO
        s.send('HELO test@test.org \r\n')
        result = s.recv(1024)

        # VRFY a user
        s.send('VRFY %s\r\n' % name.strip())
        result = s.recv(1024)

        # Check result
        if 'not implemented' in result or 'disallowed' in result:
            res = '[>] %s - VRFY Command not implemented' % ip
        elif '250' in result or ('252' in result and 'Cannot VRFY' not in result):
            res = "[>] %s - SMTP VRFY Account found: %s" % (ip, name.strip())
        else:
            res = None

        # Close and return
        s.close()
        return res

    # Check if port is open
    if not check_connect():
        c.bcolors.print_error('Error connecting: %s' % ip)
        return

    # Skim through wordlist
    results = []
    with open(c.WORDLIST_SMTP, 'r') as names:
        for name in names:
            results.append(try_vrfy(name))

    # Write results to file
    results = filter(None, results)
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
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 25

    # Output file
    enum_type = 'smtp'
    script = 'vrfy'
    output = c.get_output_file(ip, enum_type, script)

    # Start scan
    c.bcolors.print_info('ENUM - %s/%s: %s' % (enum_type, script, ip))
    exec_scan(ip, port, output)


if __name__ == '__main__':
    main()
