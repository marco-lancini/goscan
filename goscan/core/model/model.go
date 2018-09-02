package model

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"os"
	"strings"
	"sync"
)

var (
	lock sync.Mutex
)

type Step int
const (
	NOT_DEFINED Step = iota
	IMPORTED		// targets
	SWEEPED			// targets
	NEW				// hosts
	SCANNED			// hosts
)
func (s Step) String() string {
	return [...]string{"NOT_DEFINED", "IMPORTED", "SWEEPED", "NEW", "SCANNED"}[s]
}



// ---------------------------------------------------------------------------------------
// UTILS
// ---------------------------------------------------------------------------------------
func InitDB(dbpath string) *gorm.DB {
	// Create connection to DB
	db, err := gorm.Open("sqlite3", dbpath)
	if err != nil {
		fmt.Println(fmt.Sprintf("[DB ERROR] %s", err))
		os.Exit(1)
	}
	// Disable logging
	if os.Getenv("DEBUG") == "1" {
		db.LogMode(true)
	} else {
		db.LogMode(false)
	}
	// Migrate schema
	migrateDB(db)

	return db
}

func migrateDB(db *gorm.DB) {
	db.AutoMigrate(&Target{})
	db.AutoMigrate(&Service{})
	db.AutoMigrate(&Port{})
	db.AutoMigrate(&Host{})
}

// ---------------------------------------------------------------------------------------
// TARGET
// ---------------------------------------------------------------------------------------
type Target struct {
	ID      uint   `gorm:"primary_key"`
	Address string `gorm:"unique_index:idx_target_ip"`
	Step    string
}

// Print to string
func (t *Target) String() string {
	return fmt.Sprintf("%s", t.Address)
}

// Constructor
func AddTarget(db *gorm.DB, address string, step string) *Target {
	lock.Lock()
	defer lock.Unlock()

	t := &Target{
		Address: address,
		Step:    step,
	}
	db.Create(t)
	return t
}

// Getters
func GetAllTargets(db *gorm.DB) []Target {
	targets := []Target{}
	db.Find(&targets)
	return targets
}

func GetTargetByStep(db *gorm.DB, step string) []Target {
	targets := []Target{}
	db.Where("step = ?", step).Find(&targets)
	return targets
}

// ---------------------------------------------------------------------------------------
// SERVICE
// ---------------------------------------------------------------------------------------
type Service struct {
	ID      uint   `gorm:"primary_key"`
	Name    string `gorm:"unique_index:idx_service"`
	Version string
	Product string
	OsType  string
	PortID  uint `gorm:"unique_index:idx_service"`
	Port    *Port
}

// Print to string
func (s *Service) String() string {
	out := s.Name
	if s.Product != "" {
		out = fmt.Sprintf("%s [%s %s]", out, s.Product, s.Version)
	}
	return out
}

// Constructor
func AddService(db *gorm.DB, name, version, product, osType string, p *Port, pID uint) *Service {
	lock.Lock()
	defer lock.Unlock()

	t := &Service{
		Name:    name,
		Version: version,
		Product: product,
		OsType:  osType,
		Port:    p,
		PortID:  pID,
	}
	db.Create(t)
	return t
}

// Getters
func GetServiceByName(db *gorm.DB, name string) []Service {
	services := []Service{}
	db.Where("name LIKE ?", name).Find(&services)
	return services
}

func (s *Service) GetPort(db *gorm.DB) *Port {
	port := &Port{}
	db.Where("id = ?", s.PortID).Find(&port)
	return port
}


// ---------------------------------------------------------------------------------------
// PORT
// ---------------------------------------------------------------------------------------
type Port struct {
	ID       uint   `gorm:"primary_key"`
	Number   int    `gorm:"unique_index:idx_port"`
	Protocol string `gorm:"unique_index:idx_port"`
	Status   string `gorm:"unique_index:idx_port"`
	Service  Service
	HostID   uint `gorm:"unique_index:idx_port"`
	Host     *Host
}

// Print to string
func (p *Port) String() string {
	return fmt.Sprintf("%5d/%s %-8s", p.Number, p.Protocol, p.Status)
}

// Constructor
func AddPort(db *gorm.DB, number int, protocol, status string, h *Host) (*Port, bool) {
	lock.Lock()
	defer lock.Unlock()

	duplicate := false
	t := &Port{
		Number:   number,
		Protocol: protocol,
		Status:   status,
		Host:     h,
	}
	if err := db.Create(t).Error; err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			duplicate = true
		}
	}

	return t, duplicate
}

// Getters
func (p *Port) GetService(db *gorm.DB) Service {
	srv := Service{}
	db.Where("port_id = ?", p.ID).Find(&srv)
	return srv
}

func (p *Port) GetHost(db *gorm.DB) *Host {
	host := &Host{}
	db.Where("id = ?", p.HostID).Find(&host)
	return host
}



// ---------------------------------------------------------------------------------------
// HOST
// ---------------------------------------------------------------------------------------
type Host struct {
	ID      uint   `gorm:"primary_key"`
	Address string `gorm:"unique_index:idx_hostname_ip"`
	Status  string
	OS      string
	Info    string
	Ports   []Port
	Step    string
}

// Print to string
func (h *Host) String() string {
	return fmt.Sprintf("%s", h.Address)
}

// Constructor
func AddHost(db *gorm.DB, address string, status string, step string) *Host {
	lock.Lock()
	defer lock.Unlock()

	t := &Host{
		Address: address,
		Status:  status,
		Step:    step,
	}
	db.Create(t)
	return t
}

// Getters
func GetAllHosts(db *gorm.DB) []Host {
	hosts := []Host{}
	db.Find(&hosts)
	return hosts
}

func GetHostByStep(db *gorm.DB, step string) []Host {
	hosts := []Host{}
	db.Where("step = ?", step).Find(&hosts)
	return hosts
}

func GetHostByAddress(db *gorm.DB, address string) *Host {
	host := &Host{}
	db.Where("address = ?", address).First(&host)
	return host
}

func (h *Host) GetPorts(db *gorm.DB) []Port {
	ports := []Port{}
	db.Where("host_id = ?", h.ID).Find(&ports)
	return ports
}
