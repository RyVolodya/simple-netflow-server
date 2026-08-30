<p align="center">
  <img src="docs/images/logo.svg" alt="Simple NetFlow Server logo" width="96" height="96">
</p>

<h1 align="center">Simple NetFlow Server</h1>

<p align="center">
  <strong>A lightweight NetFlow collector and traffic analyzer with a modern web interface.</strong>
</p>

<p align="center">
  Monitor network traffic, analyze flows, discover top talkers, inspect conversations, and track exporters from a simple Docker-based application.
</p>

<p align="center">
  <a href="https://github.com/RyVolodya/simple-netflow-server">GitHub Repository</a>
</p>

---

## About

**Simple NetFlow Server** is a lightweight network traffic monitoring and analysis platform for collecting and analyzing flow data from routers, switches, firewalls, and other network devices.

It provides a clean web interface for traffic analysis without the complexity of large monitoring platforms. It is designed for home labs, small and medium networks, and network engineers who need a practical NetFlow analyzer.

The application runs in Docker and combines a flow collector, FastAPI backend, PostgreSQL database, and web frontend.

**Project repository:** https://github.com/RyVolodya/simple-netflow-server

## Features

### Dashboard

- Total Traffic and Total Flows
- Exporters and Interfaces
- Database Size
- Collector / Backend / Database status
- Top Source Traffic
- Top Destination Traffic
- Top Devices
- Top Applications
- Top Interfaces
- Traffic history
- Configurable analysis periods
- Drill-down from charts into filtered flow data

### Flows

Advanced filtering by time period, custom From/To range, Exporter, Interface, Source/Destination IP, Protocol and Source/Destination port.

Two modes are available:

- **Detailed** — individual raw flow records.
- **Summary** — aggregated traffic for the current filters, including IP, protocol, port, traffic, packets and flow count.

### Conversations

The **Conversations** page shows communication between hosts, aggregated as:

```text
Source IP → Destination IP
```

Each conversation includes Source IP, Destination IP, Total Traffic, Packets and Flow count. Results are ordered from highest traffic to lowest.

Available views:

- Table
- Chart
- Top 10 / 25 / 50 / 100

### Exporters

- Automatic exporter discovery
- Active / Idle status
- Last flow received
- SNMP configuration
- Device hostname discovery
- Interface discovery
- Delete exporter and associated traffic data

### SNMP Enrichment

SNMP enrichment can retrieve device hostnames, interface names and interface indexes, allowing readable interface names such as `ether1`, `VLAN100` or `GigabitEthernet0/1` instead of only numeric ifIndex values.

### Storage & Retention

Default retention:

```text
Detailed Raw Flows: 12 hours
Statistics:          30 days
```

Minimum configurable retention:

```text
Detailed Raw Flows: 1 hour
Statistics:          6 hours
```

Raw flow data uses daily PostgreSQL partitions to keep recent detailed traffic available while retaining aggregated statistics for longer periods.

### User Management

**Administrator:** full access, exporter/SNMP management, retention and application settings, users and passwords.

**User:** view dashboards, analyze flows/conversations, and change own password.

---

## Screenshots

> Store screenshots in `/docs/images/`.

### Dashboard

![Dashboard](docs/images/dashboard.png)

### Flows

![Detailed Flows](docs/images/flows.png)

### Conversations

![Conversations](docs/images/conversations.png)

### Exporters

![Exporters](docs/images/exporters.png)

### Settings

![Settings](docs/images/settings.png)

---

## Architecture

```text
Router / Switch
      │
      │ NetFlow / IPFIX
      ▼
┌───────────────┐
│ Flow Collector│
└───────┬───────┘
        ▼
┌───────────────┐
│    Backend    │
│    FastAPI    │
└───────┬───────┘
        ▼
┌───────────────┐
│  PostgreSQL   │
│ Raw + Stats   │
└───────┬───────┘
        ▼
┌───────────────┐
│ Web Frontend  │
└───────────────┘
```

Main Docker services: `frontend`, `backend`, `collector`, `postgres`.

## Installation

### Requirements

- Linux server
- Docker
- Docker Compose plugin

Clone the official repository:

```bash
git clone https://github.com/RyVolodya/simple-netflow-server.git
cd simple-netflow-server
```

Start the application:

```bash
docker compose up -d --build
```

Check status:

```bash
docker compose ps
```

## Web Interface

Default:

```text
http://SERVER-IP:8080
```

Optional `.env` setting:

```env
FRONTEND_PORT=3080
```

Restart after changing it:

```bash
docker compose down
docker compose up -d
```

## Default Login

```text
Username: admin
Password: netflow
```

> [!IMPORTANT]
> Change the default administrator password after the first login and before production use.

## NetFlow Collector

Configure devices to send flow data to:

```text
Collector IP: SERVER-IP
Collector Port: 2055/UDP
```

UFW example:

```bash
sudo ufw allow 2055/udp
```

## MikroTik Example

```routeros
/ip traffic-flow
set enabled=yes

/ip traffic-flow target
add dst-address=SERVER-IP port=2055 version=9
```

Verify:

```routeros
/ip traffic-flow print
/ip traffic-flow target print
```

## Cisco IOS Example

```cisco
ip flow-export destination SERVER-IP 2055
ip flow-export version 9
ip flow-export source GigabitEthernet0/0

interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
```

Verify:

```cisco
show ip flow export
show ip cache flow
```

## Database Design

```text
Incoming Flow
     │
     ├──── Detailed Raw Flow
     │        └── Short retention
     │
     └──── Aggregated Statistics
              └── Long retention
```

## Updating

```bash
git pull
docker compose down --remove-orphans
docker compose up -d --build --remove-orphans
```

## Logs

```bash
docker compose logs -f
docker compose logs -f backend
docker compose logs -f collector
docker compose logs -f postgres
```

## Project Goals

- Simple deployment
- Low resource usage
- Clean and responsive GUI
- Useful traffic visualization
- Fast troubleshooting
- Short-term detailed flow analysis
- Long-term aggregated statistics
- Easy Docker deployment

The goal is to provide a lightweight and practical NetFlow analyzer for everyday network engineering tasks.

## Roadmap

- Extended IPFIX support
- IPv6 analysis improvements
- DNS / reverse DNS enrichment
- ASN and GeoIP enrichment
- More conversation analytics
- Historical rollups
- Report export
- Additional SNMP information
- Notifications and alerts

## Contributing

Contributions, bug reports and feature requests are welcome.

Please use the repository issue tracker:

https://github.com/RyVolodya/simple-netflow-server/issues

When reporting an issue, include:

- Simple NetFlow Server version
- Docker version
- Device/vendor
- NetFlow/IPFIX version
- Relevant logs
- Steps to reproduce

## License

See the `LICENSE` file for license information.

## Author

Created and maintained by **RyVolodya**.

Project: https://github.com/RyVolodya/simple-netflow-server

If you find this project useful, consider giving the repository a ⭐.
