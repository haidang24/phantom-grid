package config

// SPA Configuration
const (
	SPAMagicPort         = 1337
	SPASecretToken       = "PHANTOM_GRID_SPA_2025"
	SPATokenLen          = 21
	SPAWhitelistDuration = 30
)

// Network Configuration
const (
	HoneypotPort = 9999
	SSHPort      = 22
)

// Fake ports for The Mirage (must match is_fake_port() in internal/ebpf/programs/phantom.c)
var FakePorts = []int{
	80,    // HTTP
	443,   // HTTPS
	3306,  // MySQL (fake)
	5432,  // PostgreSQL (fake)
	6379,  // Redis (fake)
	27017, // MongoDB (fake)
	8080,  // Admin Panel (fake)
	8443,  // HTTPS Alt (fake)
	9000,  // Admin Panel (fake)
	21,    // FTP (fake)
	23,    // Telnet (fake)
	3389,  // RDP (fake)
	5900,  // VNC (fake)
	1433,  // MSSQL (fake)
	1521,  // Oracle (fake)
	5433,  // PostgreSQL Alt (fake)
	11211, // Memcached (fake)
	27018, // MongoDB Shard (fake)
	9200,  // Elasticsearch (fake)
	5601,  // Kibana (fake)
	3000,  // Node.js (fake)
	5000,  // Flask (fake)
	8000,  // Django (fake)
	8888,  // Jupyter (fake)
}

// Fallback ports if honeypot port is unavailable
var FallbackPorts = []int{9998, 9997, 9996, 8888, 7777}
