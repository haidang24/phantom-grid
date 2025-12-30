# ELK Integration Guide

## Overview

Phantom Grid supports exporting security events to Elasticsearch for centralized logging, analysis, and visualization. This enables integration with the ELK stack (Elasticsearch, Logstash, Kibana) for enterprise-grade security monitoring.

## Features

- **Multiple Output Modes**: Choose between dashboard-only, ELK-only, or both
- **Buffered Export**: Efficient batch processing to reduce network overhead
- **Automatic Retry**: Failed exports are automatically retried
- **Structured Events**: All events are structured with metadata for easy querying
- **TLS Support**: Secure communication with Elasticsearch clusters

## Output Modes

### Dashboard Only (Default)

```bash
sudo ./bin/phantom-grid -interface ens33 -output dashboard
```

Shows events in the terminal dashboard only. No data is sent to Elasticsearch.

### ELK Only

```bash
sudo ./bin/phantom-grid -interface ens33 -output elk \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid
```

Sends all events to Elasticsearch. No dashboard is displayed. Useful for headless servers or when using Kibana for visualization.

### Both Dashboard and ELK

```bash
sudo ./bin/phantom-grid -interface ens33 -output both \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid
```

Shows events in the dashboard AND sends them to Elasticsearch. Best for development and testing.

## Command Line Options

### Basic ELK Options

```bash
-output string
    Output mode: 'dashboard', 'elk', or 'both' (default: "dashboard")

-elk-address string
    Elasticsearch address (default: "http://localhost:9200")
    For multiple addresses, use comma-separated: "http://es1:9200,http://es2:9200"

-elk-index string
    Elasticsearch index name (default: "phantom-grid")
```

### Authentication Options

```bash
-elk-user string
    Elasticsearch username (optional, for basic auth)

-elk-pass string
    Elasticsearch password (optional, for basic auth)
```

### TLS Options

```bash
-elk-tls
    Enable TLS for Elasticsearch connections

-elk-skip-verify
    Skip TLS certificate verification (not recommended for production)
```

## Configuration Examples

### Local Elasticsearch (Development)

```bash
sudo ./bin/phantom-grid -interface ens33 \
  -output both \
  -elk-address http://localhost:9200 \
  -elk-index phantom-grid-dev
```

### Elasticsearch Cloud (Production)

```bash
sudo ./bin/phantom-grid -interface eth0 \
  -output elk \
  -elk-address https://your-cluster.es.cloud:9243 \
  -elk-user elastic \
  -elk-pass your-password \
  -elk-tls \
  -elk-index phantom-grid-prod
```

### Multiple Elasticsearch Nodes (High Availability)

```bash
sudo ./bin/phantom-grid -interface eth0 \
  -output elk \
  -elk-address "http://es-node1:9200,http://es-node2:9200,http://es-node3:9200" \
  -elk-index phantom-grid
```

## Event Structure

All events sent to Elasticsearch follow this structure:

```json
{
  "@timestamp": "2025-12-30T10:23:45.123Z",
  "event_type": "trap_hit",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "port": 3306,
  "command": "whoami",
  "service": "ssh",
  "message": "[TRAP HIT] Connection from 192.168.1.100:54321 to port 3306",
  "risk_level": "HIGH",
  "metadata": {
    "additional_field": "value"
  }
}
```

### Event Types

- `trap_hit` - Honeypot connection detected
- `command` - Command executed in honeypot
- `spa_auth` - Successful SPA authentication
- `spa_failed` - Failed SPA authentication attempt
- `stealth_drop` - Stealth scan detected and dropped
- `os_mutation` - OS fingerprint mutation applied
- `egress_block` - Data exfiltration attempt blocked
- `connection` - General connection event
- `system` - System/status messages

### Risk Levels

- `LOW` - Informational events
- `MEDIUM` - Suspicious activity
- `HIGH` - Critical security events

## Elasticsearch Index Template

For optimal performance, create an index template:

```json
PUT _template/phantom-grid
{
  "index_patterns": ["phantom-grid*"],
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 1
  },
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "event_type": {
        "type": "keyword"
      },
      "source_ip": {
        "type": "ip"
      },
      "destination_ip": {
        "type": "ip"
      },
      "port": {
        "type": "integer"
      },
      "command": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword"
          }
        }
      },
      "service": {
        "type": "keyword"
      },
      "message": {
        "type": "text"
      },
      "risk_level": {
        "type": "keyword"
      },
      "metadata": {
        "type": "object",
        "enabled": true
      }
    }
  }
}
```

## Kibana Dashboard Setup

### 1. Create Index Pattern

1. Go to Kibana → Management → Index Patterns
2. Create index pattern: `phantom-grid*`
3. Select `@timestamp` as time field

### 2. Create Visualizations

**Top Attacker IPs:**
- Visualization Type: Data Table
- Aggregation: Terms on `source_ip.keyword`
- Sort: Descending by count

**Event Types Over Time:**
- Visualization Type: Line Chart
- X-axis: Date Histogram on `@timestamp`
- Y-axis: Count
- Split Series: Terms on `event_type.keyword`

**Risk Level Distribution:**
- Visualization Type: Pie Chart
- Slice Size: Terms on `risk_level.keyword`

**Commands Executed:**
- Visualization Type: Data Table
- Aggregation: Terms on `command.keyword`
- Sort: Descending by count

### 3. Create Dashboard

Combine visualizations into a dashboard for real-time monitoring.

## Performance Tuning

### Batch Size

Events are buffered and sent in batches. Default batch size is 100 events. Adjust in code if needed:

```go
elkConfig.BatchSize = 200  // Larger batches = fewer requests
```

### Flush Interval

Default flush interval is 5 seconds. Events are automatically flushed even if batch is not full:

```go
elkConfig.FlushInterval = 10  // Flush every 10 seconds
```

### Connection Pooling

The exporter automatically tries multiple Elasticsearch addresses if provided. Failed requests are retried with the next address.

## Troubleshooting

### Events Not Appearing in Elasticsearch

1. **Check Elasticsearch Connection:**
   ```bash
   curl http://localhost:9200
   ```

2. **Check Index Exists:**
   ```bash
   curl http://localhost:9200/_cat/indices/phantom-grid*
   ```

3. **Check Application Logs:**
   Look for `[ELK]` prefixed messages in application output.

4. **Verify Output Mode:**
   Ensure `-output elk` or `-output both` is specified.

### Authentication Errors

If using authentication:
- Verify username and password are correct
- Check Elasticsearch security settings
- Ensure user has write permissions to the index

### TLS Certificate Errors

If using TLS:
- Verify certificate is valid
- Use `-elk-skip-verify` only for testing (not production)
- Ensure Elasticsearch cluster supports TLS

### High Memory Usage

If experiencing high memory usage:
- Reduce batch size
- Increase flush interval
- Check Elasticsearch cluster health

## Best Practices

1. **Use Index Templates**: Create index templates for consistent mapping
2. **Index Lifecycle Management**: Set up ILM policies to manage index retention
3. **Separate Environments**: Use different indices for dev/staging/prod
4. **Monitor Performance**: Track export success rates and latency
5. **Secure Credentials**: Never hardcode credentials, use environment variables or secrets management
6. **High Availability**: Use multiple Elasticsearch addresses for redundancy

## Integration with Logstash

If using Logstash, you can configure it to receive events from Phantom Grid:

```ruby
input {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "phantom-grid*"
    query => '{"query": {"match_all": {}}}'
  }
}

filter {
  # Add any transformations here
}

output {
  # Send to another system, enrich data, etc.
}
```

## Example Queries

### Find All High-Risk Events

```json
GET phantom-grid/_search
{
  "query": {
    "term": {
      "risk_level": "HIGH"
    }
  }
}
```

### Find Commands from Specific IP

```json
GET phantom-grid/_search
{
  "query": {
    "bool": {
      "must": [
        {"term": {"source_ip": "192.168.1.100"}},
        {"exists": {"field": "command"}}
      ]
    }
  }
}
```

### Count Events by Type (Last 24 Hours)

```json
GET phantom-grid/_search
{
  "size": 0,
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  },
  "aggs": {
    "event_types": {
      "terms": {
        "field": "event_type.keyword",
        "size": 10
      }
    }
  }
}
```

## See Also

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Kibana Documentation](https://www.elastic.co/guide/en/kibana/current/index.html)
- [README.md](../README.md) - Main project documentation

