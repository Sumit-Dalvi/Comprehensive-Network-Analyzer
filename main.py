import socket
from scapy.all import *
import pywifi
from pywifi import const
import logging

# Configure logging
logging.basicConfig(filename='network_analyzer.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def log_and_print(message, log_level=logging.INFO):
    logging.log(log_level, message)
    print(message)

def port_scanner(target, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                log_and_print(f"Port {port} is open.")
            s.close()
        except KeyboardInterrupt:
            log_and_print("\nExiting...", logging.ERROR)
            exit()
        except Exception as e:
            log_and_print(f"Error: {e}", logging.ERROR)
            pass
    return open_ports

def packet_sniffer(interface, count):
    packets = sniff(iface=interface, count=count)
    return packets

def analyze_packets(packets):
    log_and_print("\nAnalyzing captured packets...")
    for packet in packets:
        # Log detailed packet information
        logging.info(packet.show())

def wifi_analyzer():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    results = iface.scan_results()
    log_and_print("\nWi-Fi Networks:")
    for result in results:
        log_and_print(f"SSID: {result.ssid} | BSSID: {result.bssid} | Signal Strength: {result.signal}")

if __name__ == "__main__":
    log_and_print("Welcome to the Comprehensive Network Analyzer!")
    target = input("Enter target IP address: ")
    start_port = int(input("Enter starting port number: "))
    end_port = int(input("Enter ending port number: "))
    interface = input("Enter network interface (e.g., 'eth0'): ")
    count = int(input("Enter number of packets to sniff: "))

    log_and_print("\nScanning for open ports...")
    open_ports = port_scanner(target, start_port, end_port)
    if open_ports:
        log_and_print(f"Open ports: {open_ports}")
    else:
        log_and_print("No open ports found.")

    log_and_print("\nSniffing network traffic...")
    packets = packet_sniffer(interface, count)

    if packets:
        analyze_packets(packets)
    else:
        log_and_print("No packets captured.")

    wifi_analyzer()


