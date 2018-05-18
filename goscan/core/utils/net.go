package utils

import (
	"net"
)

// Parse a string and returns the corresponding CIDR
func ParseCIDR(s string) string {
	_, ipv4Net, err := net.ParseCIDR(s)
	if err != nil {
		return ""
	}
	return ipv4Net.String()
}

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
