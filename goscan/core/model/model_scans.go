package model

import (
	"fmt"
	"sync"
)

// ---------------------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------------------
var Mutex sync.Mutex

const (
	NULL = iota
	NOT_STARTED
	IN_PROGRESS
	FAILED
	DONE
	FINISHED
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
