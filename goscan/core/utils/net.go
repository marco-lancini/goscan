package utils

import (
	"net"
	"net/http"
)

func Connected() bool {
	_, err := http.Get("https://clients3.google.com/generate_204")
	if err != nil {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------------------
// IP addresses
// ---------------------------------------------------------------------------------------
// Returns all the addresses of the local network interfaces
func ParseLocalIP() map[string]string {
	// Returns a Map of interface:subnet
	res := make(map[string]string)

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			res[i.Name] = addr.String()
			break
		}
	}
	return res
}

// Parse a string and returns the corresponding CIDR and error status
func ParseCIDR(s string) (string, error) {
	_, ipv4Net, err := net.ParseCIDR(s)
	if err != nil {
		return "", err
	}
	return ipv4Net.String(), nil
}

// Parse a string and returns the corresponding IP address, or nil
func ParseIP(s string) string {
	i := net.ParseIP(s)
	return i.String()
}

// Parse a string, regardless if it is an IP or CIDR, and returns its string representation
func ParseAddress(addr string) (string, bool) {
	cidr, err := ParseCIDR(addr)
	if err == nil {
		return cidr, true
	}

	ip := ParseIP(addr)
	if ip != "" {
		return ip, true
	}

	return "", false
}
