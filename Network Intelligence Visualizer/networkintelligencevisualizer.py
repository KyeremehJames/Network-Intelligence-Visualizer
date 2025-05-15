Threat Intelligence Visualizer

import sys
import logging
import yaml
import dpkt
import socket
from pathlib import Path
import pygeoip
import requests
from typing import Dict, List, Optional

# Configuration
CONFIG_FILE = "config/config.yaml"
LOG_FILE = "threatviz.log"

class ThreatIntelAnalyzer:
    def __init__(self):
        self.config = self._load_config()
        self.geoip_db = self._init_geoip()
        self.logger = self._init_logging()
        self.threat_feeds = self.config.get('threat_feeds', [])
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(CONFIG_FILE) as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)

    def _init_geoip(self) -> pygeoip.GeoIP:
        """Initialize GeoIP database"""
        db_path = Path(self.config.get('geoip_db_path', 'data/GeoLiteCity.dat'))
        if not db_path.exists():
            raise FileNotFoundError(f"GeoIP database not found at {db_path}")
        return pygeoip.GeoIP(str(db_path))

    def _init_logging(self):
        """Configure logging system"""
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger()

    def check_threat_feeds(self, ip: str) -> List[str]:
        """Check IP against multiple threat intelligence feeds"""
        threats = []
        
        # Local blacklist check
        if ip in self.config.get('blacklists', {}).get('local', []):
            threats.append("local_blacklist")
            
        # Dynamic threat feed checks
        for feed in self.threat_feeds:
            if feed['type'] == 'abuseipdb':
                if self._check_abuseipdb(ip, feed['api_key']):
                    threats.append("abuseipdb")
                    
        return threats

    def _check_abuseipdb(self, ip: str, api_key: str) -> bool:
        """Check IP against AbuseIPDB API"""
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            headers = {'Key': api_key, 'Accept': 'application/json'}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data['data']['abuseConfidenceScore'] > 75
        except Exception as e:
            self.logger.error(f"AbuseIPDB check failed: {e}")
        return False

    def analyze_pcap(self, pcap_path: str, output_format: str = "cli"):
        """Main analysis function"""
        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                if output_format == "kml":
                    print(self._generate_kml_header())
                
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        ip = eth.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        
                        self._process_ip(src_ip, "Source", output_format)
                        self._process_ip(dst_ip, "Destination", output_format)
                        
                    except Exception as e:
                        self.logger.debug(f"Packet processing error: {e}")
                        
                if output_format == "kml":
                    print(self._generate_kml_footer())
                    
        except FileNotFoundError:
            self.logger.error(f"PCAP file not found: {pcap_path}")
            sys.exit(1)

    def _process_ip(self, ip: str, ip_type: str, output_format: str):
        """Process individual IP address"""
        threats = self.check_threat_feeds(ip)
        if not threats:
            return
            
        geo = self.geoip_db.record_by_addr(ip)
        if not geo:
            self.logger.warning(f"Could not geolocate IP: {ip}")
            return
            
        if output_format == "cli":
            self._print_cli_report(ip, ip_type, threats, geo)
        else:
            self._generate_kml_placemark(ip, ip_type, geo)

    def _print_cli_report(self, ip: str, ip_type: str, threats: List[str], geo: Dict):
        """Generate CLI output"""
        print(f"\n[THREAT] {ip_type} IP: {ip}")
        print(f"Threat Indicators: {', '.join(threats)}")
        print(f"Location: {geo.get('city', 'Unknown')}, {geo.get('country_name', 'Unknown')}")
        print(f"Coordinates: {geo.get('latitude')}, {geo.get('longitude')}")
        print("-" * 50)

    def _generate_kml_header(self) -> str:
        """Generate KML document header"""
        return """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
  <name>Threat Intelligence Visualization</name>
  <open>1</open>
  <Style id="threatStyle">
    <LabelStyle>
      <color>ff0000ff</color>
    </LabelStyle>
  </Style>"""

    def _generate_kml_placemark(self, ip: str, ip_type: str, geo: Dict):
        """Generate KML placemark for a single IP"""
        coords = f"{geo.get('longitude')},{geo.get('latitude')}"
        print(f"""
  <Placemark>
    <name>{ip_type} IP: {ip}</name>
    <description>
      City: {geo.get('city', 'Unknown')}
      Country: {geo.get('country_name', 'Unknown')}
    </description>
    <styleUrl>#threatStyle</styleUrl>
    <Point>
      <coordinates>{coords}</coordinates>
    </Point>
  </Placemark>""")

    def _generate_kml_footer(self) -> str:
        """Generate KML document footer"""
        return """
</Document>
</kml>"""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python threatviz.py <pcap_file> [cli|kml]")
        sys.exit(1)
        
    output_format = sys.argv[2] if len(sys.argv) > 2 else "cli"
    pcap_file = sys.argv[1]
    
    analyzer = ThreatIntelAnalyzer()
    analyzer.analyze_pcap(pcap_file, output_format)
