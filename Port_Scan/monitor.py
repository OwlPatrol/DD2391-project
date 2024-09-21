from scapy.all import *
import re

# Define the suspicious pattern we're looking for (JNDI exploit pattern)
suspicious_pattern = r'\$\{jndi:(ldap|rmi|dns)://'

# Define the network interface to sniff (you may need to change this based on your system)
interface = 'en0'

# Callback function to handle each packet sniffed
def monitor_traffic(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        # Search for the suspicious pattern in the payload
        if re.search(suspicious_pattern, payload, re.IGNORECASE):
            print(f"[ALERT] Potential Log4Shell exploit attempt detected!")
            print(f"Source IP: {packet[IP].src}")
            print(f"Destination IP: {packet[IP].dst}")
            print(f"Payload: {payload}\n")

# Start sniffing on the specified network interface
print(f"[*] Starting network traffic monitoring on {interface}...")
sniff(iface=interface, filter="tcp port 80 or tcp port 443", prn=monitor_traffic, store=0)
