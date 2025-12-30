package config

// SPA Configuration
const (
	SPAMagicPort         = 1337
	SPASecretToken       = "PHANTOM_GRID_SPA_2025"
	SPATokenLen          = 21
	SPAWhitelistDuration = 30
)

// CriticalPorts are ports protected by Phantom Protocol (SPA required)
// These ports will be DROPPED unless IP is whitelisted via SPA Magic Packet
// To add more ports, update both this list AND is_critical_asset_port() in internal/ebpf/programs/phantom.c
var CriticalPorts = []int{
	22,    // SSH
	3306,  // MySQL
	5432,  // PostgreSQL
	27017, // MongoDB
	6379,  // Redis
	8080,  // Admin Panel / HTTP Proxy
	8443,  // HTTPS Admin Panel
	9000,  // Admin Panel / Portainer
	3389,  // RDP (Windows Remote Desktop)
	1433,  // MSSQL Server
	1521,  // Oracle Database
	5433,  // PostgreSQL Alt
	5985,  // WinRM HTTP
	5986,  // WinRM HTTPS
	2375,  // Docker (unencrypted)
	2376,  // Docker (TLS)
	5000,  // Docker Registry / Flask
	27018, // MongoDB Shard
	9200,  // Elasticsearch
	5601,  // Kibana
	3000,  // Node.js / Grafana
	8000,  // Django / Jupyter
	8888,  // Jupyter Notebook
	9090,  // Prometheus
	9091,  // Prometheus Pushgateway
	15672, // RabbitMQ Management
	8161,  // ActiveMQ Web Console
	8162,  // ActiveMQ Web Console (HTTPS)
	61616, // ActiveMQ
	61617, // ActiveMQ (SSL)
	2181,  // Zookeeper
	7001,  // WebLogic
	7002,  // WebLogic (SSL)
	4848,  // GlassFish Admin
	4849,  // GlassFish Admin (HTTPS)
	9990,  // WildFly Admin
	9993,  // WildFly Admin (HTTPS)
	5984,  // CouchDB
	2702,  // MS SQL Browser
	1434,  // MS SQL Monitor
	1527,  // Derby Database
	50000, // DB2
	50001, // DB2 (SSL)
	1883,  // MQTT
	8883,  // MQTT (SSL)
	61613, // STOMP
	61614, // STOMP (SSL)
	5672,  // RabbitMQ AMQP
	5671,  // RabbitMQ AMQP (SSL)
	4369,  // Erlang Port Mapper
	25672, // RabbitMQ Management (Erlang)
	11211, // Memcached
	11214, // Memcached (SSL)
	389,   // LDAP
	636,   // LDAP (SSL)
	3268,  // LDAP Global Catalog
	3269,  // LDAP Global Catalog (SSL)
	2049,  // NFS
	111,   // RPC Portmapper
}

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
