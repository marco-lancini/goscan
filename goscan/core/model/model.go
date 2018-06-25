package model

import (
	"bufio"
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

// ---------------------------------------------------------------------------------------
// UTILS
// ---------------------------------------------------------------------------------------
func InitDB() *gorm.DB {
	// Create connection to DB
	db, err := gorm.Open("sqlite3", os.Getenv("DB_PATH"))
	if err != nil {
		fmt.Println(fmt.Sprintf("[DB ERROR] %s", err))
		os.Exit(1)
	}
	// Disable logging
	if os.Getenv("DEBUG") == "0" {
		db.LogMode(false)
	}
	// Migrate schema
	migrateDB(db)

	return db
}

func ResetDB(db *gorm.DB) {
	db.DropTable(&Service{})
	db.DropTable(&Port{})
	db.DropTable(&Host{})

	db = InitDB()
}

func migrateDB(db *gorm.DB) {
	db.AutoMigrate(&Service{})
	db.AutoMigrate(&Port{})
	db.AutoMigrate(&Host{})
}

// ---------------------------------------------------------------------------------------
// SERVICE
// ---------------------------------------------------------------------------------------
type Service struct {
	gorm.Model
	Name    string `gorm:"unique_index:idx_service"`
	Version string
	Product string
	OsType  string
	PortID uint `gorm:"unique_index:idx_service"`
	Port   *Port
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
func AddService(db *gorm.DB, name, version, product, ostype string, p *Port) *Service {
	lock.Lock()
	defer lock.Unlock()

	t := &Service{
		Name:    name,
		Version: version,
		Product: product,
		OsType:  ostype,
		Port:    p,
	}
	db.Create(t)
	return t
}


// ---------------------------------------------------------------------------------------
// PORT
// ---------------------------------------------------------------------------------------
type Port struct {
	gorm.Model
	Number   int    `gorm:"unique_index:idx_port"`
	Protocol string `gorm:"unique_index:idx_port"`
	Status   string `gorm:"unique_index:idx_port"`
	Service Service
	HostID uint `gorm:"unique_index:idx_port"`
	Host   *Host
}

// Print to string
func (p *Port) String() string {
	return fmt.Sprintf("%5d/%s %-8s", p.Number, p.Protocol, p.Status)
}

// Returns true if 2 Ports are the same
func (p *Port) Equal(other Port) bool {
	return (p.Number == other.Number) && (p.Protocol == other.Protocol) && (p.HostID == other.HostID)
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

// Get service
func (p *Port) GetService(db *gorm.DB) Service {
	srv := Service{}
	db.Where("port_id = ?", p.ID).Find(&srv)
	return srv
}

// In case of duplicate, find the original port already in DB
func (p *Port) FindOriginalPort(db *gorm.DB) *Port {
	res := &Port{}
	db.Where("number = ? AND protocol = ? AND status = ? AND host_id = ?", p.Number, p.Protocol, p.Status, p.HostID).Find(&res)
	return res
}


// ---------------------------------------------------------------------------------------
// HOST
// ---------------------------------------------------------------------------------------
type Host struct {
	gorm.Model
	Address string `gorm:"unique_index:idx_hostname_ip"`
	Status  string
	OS      string
	Info    string
	Ports []Port
}

// Print to string
func (h *Host) String() string {
	return fmt.Sprintf("%s", h.Address)
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

// Constructor
func AddHost(db *gorm.DB, address string, status string) *Host {
	lock.Lock()
	defer lock.Unlock()

	t := &Host{
		Address: address,
		Status:  status,
	}
	db.Create(t)
	return t
}

func AddHostsBulk(db *gorm.DB, source_file string) {
	file, err := os.Open(source_file)
	if err != nil {
		fmt.Println(fmt.Sprintf("Error while reading source file: %s", err))
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		addr := scanner.Text()
		fmt.Println(addr)
		AddHost(db, addr, "unknown")
	}

	if err := scanner.Err(); err != nil {
		fmt.Println(fmt.Sprintf("Error while reading source file: %s", err))
	}
}

// Getters
func GetAllHosts(db *gorm.DB) []Host {
	hosts := []Host{}
	db.Find(&hosts)
	return hosts
}

func GetHostByAddress(db *gorm.DB, address string) Host {
	host := Host{}
	db.Where("address = ?", address).First(&host)
	return host
}

func (h *Host) GetPorts(db *gorm.DB) []Port {
	ports := []Port{}
	db.Where("host_id = ?", h.ID).Find(&ports)
	return ports
}

func (h *Host) GetMostRecentPorts(db *gorm.DB) []Port {
	ports := []Port{}
	temp := []Port{}

	// Find most recent scan
	db.Order("updated_at desc").Find(&temp).Limit(1)
	if len(temp) > 0 {
		recent := temp[0].UpdatedAt
		recentDayBefore := recent.AddDate(0, 0, -1)
		// Query for ports
		db.Where("host_id = ? AND updated_at BETWEEN ? AND ?", h.ID, recentDayBefore, recent).Find(&ports)
	} else {
		db.Where("host_id = ?", h.ID).Find(&ports)
	}
	return ports
}
