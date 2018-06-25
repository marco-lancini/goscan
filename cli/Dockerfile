FROM golang:1.10-stretch

# Install additional tools
RUN curl https://raw.githubusercontent.com/pentestmonkey/finger-user-enum/master/finger-user-enum.pl -o /usr/bin/finger-user-enum.pl
RUN curl https://raw.githubusercontent.com/pentestmonkey/ftp-user-enum/master/ftp-user-enum.pl -o /usr/bin/ftp-user-enum.pl
RUN curl https://raw.githubusercontent.com/pentestmonkey/smtp-user-enum/master/smtp-user-enum.pl -o /usr/bin/smtp-user-enum
RUN curl http://www.nothink.org/codes/snmpcheck/snmpcheck-1.8.pl -o /usr/bin/snmpcheck

# Update
RUN echo "deb http://deb.debian.org/debian stretch main contrib non-free" >> /etc/apt/sources.list
RUN apt-get update && apt-get install -y zip nmap netdiscover hydra sqlmap nikto

# Setup workdir
WORKDIR /go/src/goscan/

# Setup project
#COPY goscan/ /go/src/goscan/
#RUN make setup
#RUN make build

# Debug
CMD ["/bin/bash"]
