import socket
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json, csv
from colorama import init, Fore, Style
import sys  # Added for help menu fix

# Initialize colorama
init(autoreset=True)

# -------------------- Functions -------------------- #

def get_local_ip():
    """Get local IP for default host discovery"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def ping_host(ip, timeout=0.5):
    """Check if host is alive via TCP port 80"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 80))
        s.close()
        return True
    except:
        return False

def discover_hosts(subnet, max_threads=100):
    """Discover alive hosts in a subnet"""
    alive_hosts = []
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        print(f"{Fore.YELLOW}[+] Discovering hosts in {subnet}...\n")
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_ping = {executor.submit(ping_host, str(ip)): str(ip) for ip in net.hosts()}
            for future in as_completed(future_ping):
                ip = future_ping[future]
                if future.result():
                    alive_hosts.append(ip)
                    print(f"{Fore.GREEN}[+] Host alive: {ip}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")
    print(f"\n{Fore.CYAN}[+] Host discovery complete! {len(alive_hosts)} hosts alive.\n")
    return alive_hosts

def scan_port(ip, port, timeout=0.5):
    """Scan single port and try banner grabbing"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        if result == 0:
            try:
                s.send(b"Hello\r\n")
                banner = s.recv(1024).decode().strip()
                s.close()
                return port, True, banner
            except:
                return port, True, "Unknown Service"
        s.close()
        return port, False, ""
    except:
        return port, False, ""

def scan_ports(ip, start_port, end_port, max_threads=200):
    """Multi-threaded port scanning"""
    open_ports = []
    print(f"{Fore.YELLOW}[+] Scanning {ip} ports {start_port}-{end_port}...\n")
    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_scan = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in as_completed(future_scan):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))
                print(f"{Fore.GREEN}[+] Port {port} OPEN → {banner}")
            else:
                print(f"{Fore.RED}[-] Port {port} CLOSED", end="\r")
    print(f"\n{Fore.CYAN}[+] Scan complete! {len(open_ports)} open ports found.\n")
    return open_ports

def export_results(ip, results, filename, filetype="txt"):
    """Export results to TXT/CSV/JSON"""
    if filetype.lower() == "txt":
        with open(filename, "w") as f:
            f.write(f"Scan results for {ip}\n")
            for port, banner in results:
                f.write(f"Port {port} → {banner}\n")
    elif filetype.lower() == "json":
        data = [{"port": port, "banner": banner} for port, banner in results]
        with open(filename, "w") as f:
            json.dump({"host": ip, "results": data}, f, indent=4)
    elif filetype.lower() == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Port", "Banner"])
            for port, banner in results:
                writer.writerow([ip, port, banner])
    print(f"{Fore.CYAN}[+] Results saved to {filename}")

# -------------------- CLI Parsing -------------------- #

parser = argparse.ArgumentParser(
    description="PortHawk: Efficient Python CLI Port Scanner",
    usage="python porthawk.py --host <IP> --ports 1-1024 [--threads 200] [--output file.txt] \n"
          "python porthawk.py --subnet 192.168.1.0/24 --discover [--threads 100]"
)
parser.add_argument("--host", help="Target host IP")
parser.add_argument("--subnet", help="Target subnet for host discovery (e.g., 192.168.1.0/24)")
parser.add_argument("--discover", action="store_true", help="Discover hosts in subnet")
parser.add_argument("--ports", default="1-1024", help="Port range, e.g., 1-1024")
parser.add_argument("--threads", type=int, default=200, help="Number of threads")
parser.add_argument("--output", help="Save results to file (txt/json/csv)")

args = parser.parse_args()

# -------------------- Main Logic -------------------- #

# Help menu shows if no arguments are provided
if len(sys.argv) == 1:
    parser.print_help()
    exit(0)

if args.subnet and args.discover:
    alive_hosts = discover_hosts(args.subnet, max_threads=args.threads)
    print(alive_hosts)

if args.host:
    start_port, end_port = map(int, args.ports.split("-"))
    open_ports = scan_ports(args.host, start_port, end_port, max_threads=args.threads)
    if args.output:
        export_results(args.host, open_ports, args.output, filetype=args.output.split('.')[-1])
