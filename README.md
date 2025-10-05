# PortHawk-

PortHawk is a fast, multi-threaded Python CLI port scanner with host discovery and basic banner grabbing.
Designed for small LAN scanning, learning socket programming, and quick reconnaissance in authorized environments.
Host discovery in an IPv4 subnet (basic TCP probe to port 80)
Multi-threaded TCP port scanning using ThreadPoolExecutor
Basic banner grabbing (sends a small payload and tries to read a banner)
Export results to .txt, .json, or .csv
Colorized CLI output via colorama
Lightweight and dependency-minimal (only colorama required)

#Setup (one-time):

Windows / macOS / Linux — simple
Put porthawk.py in a folder (e.g., PortHawk/).

-Open a terminal / Command Prompt:

-Windows: press Win → type cmd → hit Enter
-macOS: open Terminal (Spotlight → Terminal)
-Linux: open your terminal application
(Optional but recommended) Create and activate a virtual environment:

-macOS / Linux:
python3 -m venv .venv
source .venv/bin/activate

-Windows (PowerShell):
python -m venv .venv
.\.venv\Scripts\Activate.ps1

-Windows (Command Prompt):
python -m venv .venv
.\.venv\Scripts\activate

-Install the small dependency (colorama):
pip install colorama
You’re ready — stay in the folder with porthawk.py.

#Quick Start

Clone repo:

git clone https://github.com/<your-username>/PortHawk.git
cd PortHawk

#Run a simple scan:

python porthawk.py --host 192.168.1.10 --ports 1-1024


#Discover hosts in subnet:

python porthawk.py --subnet 192.168.1.0/24 --discover

#Installation

Create a virtual environment (recommended) and install dependencies:

python -m venv .venv
source .venv/bin/activate   # macOS / Linux
.venv\Scripts\activate      # Windows

pip install colorama


Optionally add a requirements.txt:

colorama>=0.4.6

#Usage & Examples
Syntax
python porthawk.py [--host IP] [--subnet CIDR --discover] [--ports START-END] [--threads N] [--output filename]

#Examples

1) Scan a host for ports 1–1024

python porthawk.py --host 192.168.1.10 --ports 1-1024


2) Scan a smaller range and save to JSON

python porthawk.py --host 10.0.0.5 --ports 20-80 --output results.json


3) Discover live hosts in a subnet

python porthawk.py --subnet 192.168.1.0/24 --discover


4) Tune threads for faster scan (use with caution)

python porthawk.py --host 192.168.1.10 --ports 1-65535 --threads 400


#Note: Increasing threads speeds scanning but raises CPU/network load and may trigger IDS/IPS.

#Arguments / Flags :


--host
Target host IP to scan (e.g. 192.168.1.10).

--subnet
Target subnet for discovery (CIDR notation, e.g. 192.168.1.0/24).

--discover
Use along with --subnet to perform host discovery (probes port 80).

--ports (default 1-1024)
Port range in the form START-END (e.g. 20-80).

--threads (default 200)
Number of concurrent worker threads for scanning / discovery.

--output
Save results to a file. Extension determines format: .txt, .json, .csv.

#Output Formats:
TXT
Scan results for 192.168.1.10
Port 22 → SSH Service
Port 80 → Apache httpd

JSON
{
  "host": "192.168.1.10",
  "results": [
    {"port": 22, "banner": "SSH-2.0-OpenSSH_7.6"},
    {"port": 80, "banner": "Apache/2.4.29 (Ubuntu)"}
  ]
}

CSV
Host,Port,Banner
192.168.1.10,22,SSH-2.0-OpenSSH_7.6
192.168.1.10,80,Apache/2.4.29 (Ubuntu)

#Code Walkthrough:

get_local_ip() — tries to find a local IP by connecting to 8.8.8.8. Fallback 127.0.0.1.

ping_host(ip, timeout) — attempts TCP connect on port 80 to determine liveliness.

discover_hosts(subnet, max_threads) — builds IPv4Network and concurrently pings hosts.

scan_port(ip, port, timeout) — tries connect_ex, and if open attempts a small send to grab a banner.

scan_ports(ip, start_port, end_port, max_threads) — concurrent scanning of range.

export_results(ip, results, filename, filetype) — writes txt, json, or csv.


#Troubleshooting & FAQ

Q: Script fails with ValueError: not enough values to unpack (expected 2, got 1)
A: This happens when --ports value is not in start-end format. Use --ports 1-1024.

Q: Scan too slow / too many timeouts
A: Lower --threads or increase the socket timeout in code. Also ensure no firewall is blocking probes.

Q: I get permission errors
A: Running network scans may require proper permissions; ensure you have authorization to scan the target network.

Q: Banners are empty
A: Many modern services do not respond to simple banner grab attempts or require protocol-specific handshakes. Banner grabbing here is best-effort.

Q: I want UDP scans or stealth scans
A: PortHawk currently supports TCP connect-style scanning. For UDP or stealth techniques, consider using nmap or extending the script.

Security & Legal

Important: Only scan networks and hosts you own or have explicit permission to test. Unauthorized scanning is illegal in many jurisdictions and can lead to disciplinary or criminal action. Use PortHawk responsibly.
