package config

import "fmt"

// PortDefinition represents a port with metadata
type PortDefinition struct {
	Port        int
	Name        string
	Description string
	Category    string
	Alias       string // For generating C macro name
}

// PortCategory groups ports by purpose
const (
	CategoryCore        = "core"
	CategoryDatabase    = "database"
	CategoryAdmin       = "admin"
	CategoryRemote      = "remote"
	CategoryContainer   = "container"
	CategoryApplication = "application"
	CategoryDirectory   = "directory"
	CategoryCache       = "cache"
	CategoryFile        = "file"
	CategoryMessaging   = "messaging"
)

// CriticalPortDefinitions is the single source of truth for protected ports
// This list is used to generate both Go config and eBPF C code
var CriticalPortDefinitions = []PortDefinition{
	// Core Services
	{22, "SSH", "Secure Shell", CategoryCore, "SSH_PORT"},

	// Databases
	{3306, "MySQL", "MySQL Database", CategoryDatabase, "MYSQL_PORT"},
	{5432, "PostgreSQL", "PostgreSQL Database", CategoryDatabase, "POSTGRES_PORT"},
	{5433, "PostgreSQL Alt", "PostgreSQL Alternative Port", CategoryDatabase, "POSTGRES_ALT_PORT"},
	{27017, "MongoDB", "MongoDB Database", CategoryDatabase, "MONGODB_PORT"},
	{27018, "MongoDB Shard", "MongoDB Shard Port", CategoryDatabase, "MONGODB_SHARD_PORT"},
	{6379, "Redis", "Redis Cache/Database", CategoryDatabase, "REDIS_PORT"},
	{1433, "MSSQL", "Microsoft SQL Server", CategoryDatabase, "MSSQL_PORT"},
	{2702, "MSSQL Browser", "MSSQL Browser Service", CategoryDatabase, "MSSQL_BROWSER_PORT"},
	{1434, "MSSQL Monitor", "MSSQL Monitor Service", CategoryDatabase, "MSSQL_MONITOR_PORT"},
	{1521, "Oracle", "Oracle Database", CategoryDatabase, "ORACLE_PORT"},
	{1527, "Derby", "Apache Derby Database", CategoryDatabase, "DERBY_PORT"},
	{50000, "DB2", "IBM DB2 Database", CategoryDatabase, "DB2_PORT"},
	{50001, "DB2 SSL", "IBM DB2 Database (SSL)", CategoryDatabase, "DB2_SSL_PORT"},

	// Admin Panels & Management
	{8080, "Admin Panel 1", "HTTP Admin Panel / Proxy", CategoryAdmin, "ADMIN_PANEL_PORT_1"},
	{8443, "Admin Panel 2", "HTTPS Admin Panel", CategoryAdmin, "ADMIN_PANEL_PORT_2"},
	{9000, "Admin Panel 3", "Admin Panel / Portainer", CategoryAdmin, "ADMIN_PANEL_PORT_3"},
	{9200, "Elasticsearch", "Elasticsearch", CategoryAdmin, "ELASTICSEARCH_PORT"},
	{5601, "Kibana", "Kibana Dashboard", CategoryAdmin, "KIBANA_PORT"},
	{3000, "Grafana", "Grafana / Node.js", CategoryAdmin, "GRAFANA_PORT"},
	{9090, "Prometheus", "Prometheus Metrics", CategoryAdmin, "PROMETHEUS_PORT"},
	{9091, "Prometheus Push", "Prometheus Pushgateway", CategoryAdmin, "PROMETHEUS_PUSH_PORT"},
	{15672, "RabbitMQ Mgmt", "RabbitMQ Management", CategoryAdmin, "RABBITMQ_MGMT_PORT"},
	{25672, "RabbitMQ Mgmt Erlang", "RabbitMQ Management (Erlang)", CategoryAdmin, "RABBITMQ_MGMT_ERLANG_PORT"},
	{5984, "CouchDB", "CouchDB", CategoryAdmin, "COUCHDB_PORT"},
	{8161, "ActiveMQ Web", "ActiveMQ Web Console", CategoryAdmin, "ACTIVEMQ_WEB_PORT"},
	{8162, "ActiveMQ Web SSL", "ActiveMQ Web Console (HTTPS)", CategoryAdmin, "ACTIVEMQ_WEB_SSL_PORT"},
	{61616, "ActiveMQ", "ActiveMQ", CategoryAdmin, "ACTIVEMQ_PORT"},
	{61617, "ActiveMQ SSL", "ActiveMQ (SSL)", CategoryAdmin, "ACTIVEMQ_SSL_PORT"},
	{2181, "Zookeeper", "Apache Zookeeper", CategoryAdmin, "ZOOKEEPER_PORT"},
	{7001, "WebLogic", "Oracle WebLogic", CategoryAdmin, "WEBLOGIC_PORT"},
	{7002, "WebLogic SSL", "Oracle WebLogic (SSL)", CategoryAdmin, "WEBLOGIC_SSL_PORT"},
	{4848, "GlassFish Admin", "GlassFish Admin Console", CategoryAdmin, "GLASSFISH_ADMIN_PORT"},
	{4849, "GlassFish Admin SSL", "GlassFish Admin Console (HTTPS)", CategoryAdmin, "GLASSFISH_ADMIN_SSL_PORT"},
	{9990, "WildFly Admin", "WildFly Admin Console", CategoryAdmin, "WILDFLY_ADMIN_PORT"},
	{9993, "WildFly Admin SSL", "WildFly Admin Console (HTTPS)", CategoryAdmin, "WILDFLY_ADMIN_SSL_PORT"},

	// Remote Access
	{3389, "RDP", "Windows Remote Desktop", CategoryRemote, "RDP_PORT"},
	{5985, "WinRM HTTP", "Windows Remote Management (HTTP)", CategoryRemote, "WINRM_HTTP_PORT"},
	{5986, "WinRM HTTPS", "Windows Remote Management (HTTPS)", CategoryRemote, "WINRM_HTTPS_PORT"},

	// Container Services
	{2375, "Docker", "Docker (unencrypted)", CategoryContainer, "DOCKER_PORT"},
	{2376, "Docker TLS", "Docker (TLS)", CategoryContainer, "DOCKER_TLS_PORT"},
	{5000, "Docker Registry", "Docker Registry / Flask", CategoryContainer, "DOCKER_REGISTRY_PORT"},

	// Application Frameworks
	{3000, "Node.js", "Node.js / Grafana", CategoryApplication, "NODEJS_PORT"},
	{5000, "Flask", "Flask / Docker Registry", CategoryApplication, "FLASK_PORT"},
	{8000, "Django", "Django / Jupyter", CategoryApplication, "DJANGO_PORT"},
	{8888, "Jupyter", "Jupyter Notebook", CategoryApplication, "JUPYTER_PORT"},

	// Directory Services
	{389, "LDAP", "LDAP", CategoryDirectory, "LDAP_PORT"},
	{636, "LDAP SSL", "LDAP (SSL)", CategoryDirectory, "LDAP_SSL_PORT"},
	{3268, "LDAP GC", "LDAP Global Catalog", CategoryDirectory, "LDAP_GC_PORT"},
	{3269, "LDAP GC SSL", "LDAP Global Catalog (SSL)", CategoryDirectory, "LDAP_GC_SSL_PORT"},

	// Cache Services
	{11211, "Memcached", "Memcached", CategoryCache, "MEMCACHED_PORT"},
	{11214, "Memcached SSL", "Memcached (SSL)", CategoryCache, "MEMCACHED_SSL_PORT"},

	// File Services
	{2049, "NFS", "Network File System", CategoryFile, "NFS_PORT"},
	{111, "RPC Portmapper", "RPC Portmapper", CategoryFile, "RPC_PORTMAPPER_PORT"},

	// Messaging Protocols
	{1883, "MQTT", "MQTT", CategoryMessaging, "MQTT_PORT"},
	{8883, "MQTT SSL", "MQTT (SSL)", CategoryMessaging, "MQTT_SSL_PORT"},
	{61613, "STOMP", "STOMP", CategoryMessaging, "STOMP_PORT"},
	{61614, "STOMP SSL", "STOMP (SSL)", CategoryMessaging, "STOMP_SSL_PORT"},
	{5672, "RabbitMQ AMQP", "RabbitMQ AMQP", CategoryMessaging, "RABBITMQ_AMQP_PORT"},
	{5671, "RabbitMQ AMQP SSL", "RabbitMQ AMQP (SSL)", CategoryMessaging, "RABBITMQ_AMQP_SSL_PORT"},
	{4369, "Erlang Portmapper", "Erlang Port Mapper", CategoryMessaging, "ERLANG_PORTMAPPER_PORT"},
}

// FakePortDefinitions defines ports for honeypot deception
var FakePortDefinitions = []PortDefinition{
	{80, "HTTP", "HTTP Web Server", CategoryApplication, "HTTP_PORT"},
	{443, "HTTPS", "HTTPS Web Server", CategoryApplication, "HTTPS_PORT"},
	{3306, "MySQL Fake", "MySQL (fake honeypot)", CategoryDatabase, "MYSQL_FAKE_PORT"},
	{5432, "PostgreSQL Fake", "PostgreSQL (fake honeypot)", CategoryDatabase, "POSTGRES_FAKE_PORT"},
	{6379, "Redis Fake", "Redis (fake honeypot)", CategoryDatabase, "REDIS_FAKE_PORT"},
	{27017, "MongoDB Fake", "MongoDB (fake honeypot)", CategoryDatabase, "MONGODB_FAKE_PORT"},
	{8080, "Admin Panel Fake", "Admin Panel (fake)", CategoryAdmin, "ADMIN_PANEL_FAKE_PORT"},
	{8443, "HTTPS Alt Fake", "HTTPS Alternative (fake)", CategoryAdmin, "HTTPS_ALT_FAKE_PORT"},
	{9000, "Admin Panel Fake 2", "Admin Panel (fake)", CategoryAdmin, "ADMIN_PANEL_FAKE_PORT_2"},
	{21, "FTP", "FTP Server", CategoryFile, "FTP_PORT"},
	{23, "Telnet", "Telnet Server", CategoryRemote, "TELNET_PORT"},
	{3389, "RDP Fake", "RDP (fake honeypot)", CategoryRemote, "RDP_FAKE_PORT"},
	{5900, "VNC", "VNC Server", CategoryRemote, "VNC_PORT"},
	{1433, "MSSQL Fake", "MSSQL (fake honeypot)", CategoryDatabase, "MSSQL_FAKE_PORT"},
	{1521, "Oracle Fake", "Oracle (fake honeypot)", CategoryDatabase, "ORACLE_FAKE_PORT"},
	{5433, "PostgreSQL Alt Fake", "PostgreSQL Alternative (fake)", CategoryDatabase, "POSTGRES_ALT_FAKE_PORT"},
	{11211, "Memcached Fake", "Memcached (fake)", CategoryCache, "MEMCACHED_FAKE_PORT"},
	{27018, "MongoDB Shard Fake", "MongoDB Shard (fake)", CategoryDatabase, "MONGODB_SHARD_FAKE_PORT"},
	{9200, "Elasticsearch Fake", "Elasticsearch (fake)", CategoryAdmin, "ELASTICSEARCH_FAKE_PORT"},
	{5601, "Kibana Fake", "Kibana (fake)", CategoryAdmin, "KIBANA_FAKE_PORT"},
	{3000, "Node.js Fake", "Node.js (fake)", CategoryApplication, "NODEJS_FAKE_PORT"},
	{5000, "Flask Fake", "Flask (fake)", CategoryApplication, "FLASK_FAKE_PORT"},
	{8000, "Django Fake", "Django (fake)", CategoryApplication, "DJANGO_FAKE_PORT"},
	{8888, "Jupyter Fake", "Jupyter (fake)", CategoryApplication, "JUPYTER_FAKE_PORT"},
}

// GetCriticalPorts returns list of critical port numbers
func GetCriticalPorts() []int {
	ports := make([]int, len(CriticalPortDefinitions))
	for i, def := range CriticalPortDefinitions {
		ports[i] = def.Port
	}
	return ports
}

// GetFakePorts returns list of fake port numbers
func GetFakePorts() []int {
	ports := make([]int, len(FakePortDefinitions))
	for i, def := range FakePortDefinitions {
		ports[i] = def.Port
	}
	return ports
}

// FindPortDefinition finds a port definition by port number
func FindPortDefinition(port int) *PortDefinition {
	for i := range CriticalPortDefinitions {
		if CriticalPortDefinitions[i].Port == port {
			return &CriticalPortDefinitions[i]
		}
	}
	for i := range FakePortDefinitions {
		if FakePortDefinitions[i].Port == port {
			return &FakePortDefinitions[i]
		}
	}
	return nil
}

// ValidatePorts validates port configuration for consistency
func ValidatePorts() error {
	// Check for duplicates in critical ports
	seen := make(map[int]bool)
	for _, def := range CriticalPortDefinitions {
		if seen[def.Port] {
			return fmt.Errorf("duplicate critical port: %d (%s)", def.Port, def.Name)
		}
		seen[def.Port] = true
	}

	// Check port ranges
	for _, def := range CriticalPortDefinitions {
		if def.Port < 1 || def.Port > 65535 {
			return fmt.Errorf("invalid port range: %d (%s)", def.Port, def.Name)
		}
	}

	return nil
}
