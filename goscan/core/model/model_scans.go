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
