from scapy.all import sniff, get_if_list, DHCP, BOOTP
from scapy.layers.inet import IP, TCP, UDP
import os
from datetime import datetime

LOG_FILE_PATH = ""

# Terminalde şekil ve renk desteği
def print_boxed_text(text, width=60):
    print(f"\n+{'-' * width}+")
    print(f"| {text:^{width - 2}} |")
    print(f"+{'-' * width}+\n")

def print_table_row(columns, widths):
    row = "|"
    for i, column in enumerate(columns):
        row += f" {str(column):<{widths[i]}} |"
    print(row)

def color_packet(pkt, blocked=False):
    """Colorizes the packet summary based on its type."""
    if blocked:
        return '\033[91m' + str(pkt.summary()) + '\033[0m'  # Red for blocked
    elif TCP in pkt:
        return '\033[94m' + str(pkt.summary()) + '\033[0m'  # Blue for TCP
    elif UDP in pkt:
        if DHCP in pkt:
            return '\033[95m' + str(pkt.summary()) + '\033[0m'  # Magenta for DHCP
        return '\033[92m' + str(pkt.summary()) + '\033[0m'  # Green for UDP
    else:
        return '\033[93m' + str(pkt.summary()) + '\033[0m'  # Yellow for others

def analyze_dhcp(pkt):
    if DHCP in pkt:
        dhcp_details = "DHCP Packet Details:\n"
        dhcp_options = pkt[DHCP].options
        for opt in dhcp_options:
            if isinstance(opt, tuple):
                dhcp_details += f"{opt[0]}: {opt[1]}\n"
            else:
                dhcp_details += f"{opt}\n"
        print_boxed_text(dhcp_details)
        return dhcp_details

def log_action(action, reason, pkt, packet_type, port):
    """Logs the actions taken on packets inside a log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    port_name = "Unknown"
    if packet_type == 'TCP':
        port_name = "TCP Port"
    elif packet_type == 'UDP':
        port_name = "UDP Port"
    elif packet_type == 'DHCP':
        port_name = "DHCP"

    log_entry = f"{timestamp} - {action} - {reason} - Blocked Packet: {pkt.summary()} - Packet Type: {packet_type} - Port: {port} - Port Name: {port_name}\n"
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(log_entry)

def packet_handler(pkt):
    protocol = None
    port = None
    action = None
    reason = None

    if IP in pkt:
        protocol = pkt[IP].proto

    if TCP in pkt:
        port = pkt[TCP].sport
        protocol = 'TCP'
    elif UDP in pkt:
        port = pkt[UDP].sport
        protocol = 'UDP'
        if DHCP in pkt:
            protocol = 'DHCP'

    dangerous_tcp_ports = [21, 23, 25, 80, 110, 143, 443, 445, 3389]
    dangerous_udp_ports = [53, 67, 68, 137, 138, 139]

    if protocol == 'TCP' and port in dangerous_tcp_ports:
        action = "Blocked"
        reason = "Dangerous TCP port"
        os.system(f"sudo iptables -A INPUT -p tcp --sport {port} -j DROP")
        print_boxed_text(f"THREAT DETECTED: {reason}", width=60)
        print(color_packet(pkt, blocked=True))
    elif protocol == 'UDP' and port in dangerous_udp_ports:
        action = "Blocked"
        reason = "Dangerous UDP port"
        os.system(f"sudo iptables -A INPUT -p udp --sport {port} -j DROP")
        print_boxed_text(f"THREAT DETECTED: {reason}", width=60)
        print(color_packet(pkt, blocked=True))
    elif protocol == 'DHCP':
        action = "Blocked"
        reason = "Dangerous DHCP packet"
        analyze_dhcp(pkt)
        os.system("sudo iptables -A INPUT -p udp --dport 67 -j DROP")
        print_boxed_text(f"THREAT DETECTED: {reason}", width=60)
        print(color_packet(pkt, blocked=True))

    if action:
        log_action(action, reason, pkt, protocol, port)
    else:
        print_table_row(["Protocol", "Port", "Summary"], [10, 10, 40])
        print_table_row([protocol, port, pkt.summary()], [10, 10, 40])
        print(color_packet(pkt))

def get_user_input():
    """Gets user input for the interface and log file path."""
    global LOG_FILE_PATH

    interfaces = get_if_list()
    print_boxed_text("SELECT NETWORK INTERFACE", width=60)
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")
    
    selected_interface = int(input("\nEnter your selection (number): ")) - 1
    if selected_interface < 0 or selected_interface >= len(interfaces):
        print_boxed_text("INVALID SELECTION!", width=60)
        return None, None

    interface = interfaces[selected_interface]

    LOG_FILE_PATH = input("Enter the log file path (e.g., /home/user/log.txt): ")
    if not LOG_FILE_PATH:
        print_boxed_text("INVALID FILE PATH!", width=60)
        return None, None

    return interface, LOG_FILE_PATH

def main():
    print_boxed_text("SNIFF AND BLOCK", width=60)
    interface, log_file_path = get_user_input()
    if interface and log_file_path:
        print_boxed_text(f"LISTENING ON {interface.upper()}...", width=60)
        sniff(iface=interface, prn=packet_handler, store=False)
    else:
        print_boxed_text("PROGRAM TERMINATED.", width=60)

if __name__ == "__main__":
    main()
