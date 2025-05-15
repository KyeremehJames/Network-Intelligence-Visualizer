# Network Intelligence Visualizer

![Network Visualization Example](docs/visualization-example.png)

A Python-based security tool that analyzes network traffic, identifies suspicious IP addresses, and visualizes their geographical locations on Google Maps.

## Features

- **PCAP Analysis**: Parses network packet captures to extract source/destination IPs
- **Threat Detection**: Checks IPs against configurable blacklists
- **Geolocation**: Maps IP addresses to physical locations using GeoIP
- **Visualization**: Generates KML files for Google Maps integration
- **Multi-Output Formats**:
  - Command-line reporting
  - Interactive map visualizations

## Prerequisites

- Python 3.8+
- GeoLiteCity database (free version available)
- Required Python packages:
  ```bash
  pip install pygeoip dpkt

Installation

    Clone the repository:
    bash

    git clone https://github.com/yourusername/network-intelligence-visualizer.git
    cd network-intelligence-visualizer

    Download the GeoLiteCity database:

        Obtain from MaxMind: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

        Place in project directory as data/GeoLiteCity.dat

Usage
Basic Command
bash

python networkintelligencevisualizer.py <username> <password> <output_format>

Output Formats

    CLI (Command Line Interface):
    bash

python networkintelligencevisualizer.py admin admin123 cli

Displays threat information in terminal.

KML (Google Maps Visualization):
bash

    python networkintelligencevisualizer.py admin admin123 kml > threats.kml

    Generates KML file for import into Google My Maps.

Authentication

Default credentials:

    Username: admin

    Password: admin123

Note: Change these in the source code before production use.
Configuration

Modify the following in networkintelligencevisualizer.py:
python

# IP Blacklist
black_listed_ip = ['217.168.1.2', '192.37.115.0'] 

# Authentication
auth_users = {"admin": "admin123"}

Sample Output
Command Line Output

-------------------------------------------------------------------------------------------------
[+] Source IP: 192.37.115.0 ------> Destination IP: 192.168.1.100
Source IP Information:

[*] Target : 192.37.115.0 Geo Located.

[+] City: Berlin, Region : BE, Country: Germany

[+] Latitude : 52.52, Longitude : 13.40

KML Visualization

Google Maps Visualization
Security Considerations

    Always obtain proper authorization before monitoring network traffic

    Change default credentials before deployment

    Use in compliance with all applicable laws and regulations
