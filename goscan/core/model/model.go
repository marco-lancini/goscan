package model

import (
	"fmt"
)

// ---------------------------------------------------------------------------------------
// SCAN STRUCTURE
// ---------------------------------------------------------------------------------------
type Scan struct {
	Name      string
	Target    string
	Status    int
	Outfolder string
	Outfile   string
	Cmd       string
	Result    []byte
}

func (s *Scan) String() string {
	return fmt.Sprintf("Target: %s [%d]", s.Target, s.Status)
}

// ---------------------------------------------------------------------------------------
// ENUMERATE STRUCTURE
// ---------------------------------------------------------------------------------------
type Enumeration struct {
	Target    *Host
	Outfolder string
	Kind      string
	Status    int
	Result    []byte
	Polite    string
}

func (e *Enumeration) String() string {
	return fmt.Sprintf("Enumeration [%s]: %s [%d]", e.Kind, e.Target.Address, e.Status)
}

// ---------------------------------------------------------------------------------------
// SERVICE
// ---------------------------------------------------------------------------------------
type Service struct {
	Name    string
	Version string
	Product string
	OsType  string
}

func (s *Service) String() string {
	return fmt.Sprintf("%s%s - %s", s.Name, s.Version, s.Product)
}

// ---------------------------------------------------------------------------------------
// PORT
// ---------------------------------------------------------------------------------------
type Port struct {
	Number   int
	Protocol string
	Status   string
	Service  Service
}

func (p *Port) String() string {
	return fmt.Sprintf("%5d/%s %-8s: %s", p.Number, p.Protocol, p.Status, p.Service)
}

// Returns true if 2 Ports are the same
func (p *Port) Equal(other Port) bool {
	return (p.Number == other.Number) && (p.Protocol == other.Protocol)
}

// ---------------------------------------------------------------------------------------
// HOST
// ---------------------------------------------------------------------------------------
type Host struct {
	Address string
	Status  string
	OS      string
	Ports   []Port
}

func (h *Host) String() string {
	out := fmt.Sprintf("%s - %s", h.Status, h.Address)
	if h.OS != "" {
		out = fmt.Sprintf("%s [%s] ", out, h.OS)
	}
	for i := 0; i < len(h.Ports); i++ {
		out = fmt.Sprintf("%s [%s]", out, h.Ports[i].String())
	}
	return out
}

// Add port to the list only if it's new
func (h *Host) AddPort(newPort Port) {

	existing := false
	for _, p := range h.Ports {
		if p.Equal(newPort) {
			existing = true
		}
	}
	if existing == false {
		h.Ports = append(h.Ports, newPort)
	}
}
