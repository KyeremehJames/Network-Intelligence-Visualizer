# 🌐 Network Intelligence Visualizer 🔍

![Network Visualization Dashboard](docs/demo.gif)  
*Figure 1: Interactive threat visualization on Google Maps*

## ✨ Features

| Feature | Emoji | Description |
|---------|-------|-------------|
| **PCAP Analysis** | 📦 | Parses network packet captures |
| **Threat Detection** | 🚨 | Identifies malicious IPs |
| **GeoIP Mapping** | 🌍 | Visualizes IP locations globally |
| **Multi-Output** | 📊 | CLI reports & KML maps |

## 🛠️ Installation

```bash
# Clone with git
git clone https://github.com/yourusername/network-intelligence-visualizer.git
cd network-intelligence-visualizer

# Install dependencies
pip install -r requirements.txt

# Download GeoIP database
wget -P data/ https://example.com/GeoLiteCity.dat

Installation Screenshot
Figure 2: Installation process
🚀 Usage
🔧 Basic Command
bash

python networkintelligencevisualizer.py <username> <password> <mode>

📟 CLI Mode
bash

python networkintelligencevisualizer.py admin admin123 cli

CLI Output
*Figure 3: Command-line threat analysis*
🗺 KML Mode
bash

python networkintelligencevisualizer.py admin admin123 kml > threats.kml

Google Maps Visualization
Figure 4: Interactive threat map
⚙️ Configuration
python

# 📁 networkintelligencevisualizer.py

# 🔒 Authentication
auth_users = {
    "admin": "securepassword123",  # 👈 Change this!
    "analyst": "complex!pass321"
}

# 🚫 Threat Intelligence
black_listed_ip = [
    '217.168.1.2',  # Known malicious IP
    '192.37.115.0'  # Suspicious host
]

📊 Sample Outputs
🔍 Threat Analysis Report

[🚨 ALERT] Suspicious connection detected!
├─ Source: 192.37.115.0 (Berlin, DE)
├─ Destination: 192.168.1.100
└─ Confidence: 92%

🌐 GeoIP Visualization

GeoIP Heatmap
Figure 5: Threat concentration heatmap
🔒 Security Notice

⚠️ Important Usage Guidelines:

    Always obtain proper authorization

    Never run on production networks

    Rotate credentials regularly

    Comply with local privacy laws

🤝 Contributing

💡 Pro Tip: Combine with Wireshark for advanced analysis!
