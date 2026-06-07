import sys
import signal
import os
from datetime import datetime
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, ifaces
from colorama import init, Fore, Style

# This makes colors work properly on Windows
init(autoreset=True)


# ── Settings ─────────────────────────────────────────────────
# Index 18 is the Wi-Fi card (Realtek, IP: 172.20.10.5)
# You can change this number if you switch networks
MY_WIFI_INTERFACE = ifaces.dev_from_index(18)

# If the user typed a filter like "tcp" or "port 80", use it
# Otherwise capture everything
TRAFFIC_FILTER = sys.argv[1] if len(sys.argv) > 1 else ""

# Where to save the capture log
LOG_FOLDER = "logs"


# ── Counters (we track these while the sniffer runs) ─────────
total_packets   = 0
protocol_counts = defaultdict(int)   # how many TCP, UDP, ICMP...
app_counts      = defaultdict(int)   # how many HTTPS, DNS, SSH...
talker_counts   = defaultdict(int)   # which IP sent the most packets
seen_domains    = []                 # every domain name we spotted
session_start   = datetime.now()


# ── Log file (every capture gets its own timestamped file) ───
os.makedirs(LOG_FOLDER, exist_ok=True)
log_filename = os.path.join(
    LOG_FOLDER,
    f"capture_{session_start.strftime('%Y%m%d_%H%M%S')}.log"
)
log_file = open(log_filename, "w", encoding="utf-8")


def write(line):
    """
    Print a line to the screen AND save it to the log file.
    We strip the color codes before saving so the log file
    stays clean and readable.
    """
    print(line)
    clean_line = line
    for color_code in [
        Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.CYAN,
        Fore.MAGENTA, Fore.WHITE, Fore.BLUE,
        Style.BRIGHT, Style.RESET_ALL, "\x1b[0m"
    ]:
        clean_line = clean_line.replace(color_code, "")
    log_file.write(clean_line + "\n")


# ── Port → App name lookup table ─────────────────────────────
# When we see a packet going to port 443, we know it's HTTPS.
# This table maps the most common port numbers to their names.
KNOWN_PORTS = {
    20:    "FTP-Data",
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP",
    68:    "DHCP",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    465:   "SMTPS",
    587:   "SMTP",
    993:   "IMAPS",
    995:   "POP3S",
    1194:  "OpenVPN",
    1433:  "MSSQL",
    3306:  "MySQL",
    3389:  "RDP",
    5222:  "XMPP",
    5228:  "Google-Push",
    5353:  "mDNS",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter",
    27017: "MongoDB",
}

def get_app_name(source_port, destination_port):
    """
    Try to figure out what application a packet belongs to
    by looking up its port number. We check the destination
    port first, then the source port, then give up and just
    show the number.
    """
    return (
        KNOWN_PORTS.get(destination_port) or
        KNOWN_PORTS.get(source_port) or
        f"Port-{destination_port}"
    )


# ── Utility functions ─────────────────────────────────────────

def separator(style="double"):
    """Draw a horizontal line for visual separation."""
    char = "═" if style == "double" else "─"
    return f"{Style.BRIGHT}{char * 60}{Style.RESET_ALL}"


def read_payload(packet, max_chars=100):
    """
    Try to read the raw content of a packet as text.
    If bytes aren't printable (like encrypted data),
    we replace them with dots so the output stays clean.
    Returns None if there's no payload.
    """
    if not packet.haslayer(Raw):
        return None
    try:
        raw_bytes = packet[Raw].load
        text = raw_bytes.decode("utf-8", errors="replace")
        readable = ''.join(c if c.isprintable() else '.' for c in text)
        return readable[:max_chars]
    except Exception:
        return repr(raw_bytes[:50])


def explain_flags(flags):
    """
    TCP flags are letters like 'PA' or 'S'.
    This turns them into plain English like 'PUSH + ACK'.
    Flags tell us what stage of the conversation we're in.
    """
    flags = str(flags)
    meanings = []
    if "S" in flags: meanings.append("SYN")      # starting a connection
    if "A" in flags: meanings.append("ACK")      # acknowledging data
    if "P" in flags: meanings.append("PUSH")     # sending data now
    if "F" in flags: meanings.append("FIN")      # ending a connection
    if "R" in flags: meanings.append("RST")      # forcefully closing
    if "U" in flags: meanings.append("URG")      # urgent data
    return " + ".join(meanings) if meanings else flags


def read_dns(packet):
    """
    If this is a DNS packet, extract the domain name being
    looked up or the IP address being returned.
    DNS is how your computer turns 'google.com' into an IP.
    """
    lines = []
    if not packet.haslayer(DNS):
        return lines

    dns = packet[DNS]

    # qr=0 means it's a question (your PC asking for an IP)
    if dns.qr == 0 and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
        lines.append(f"  {Fore.CYAN}DNS Question : {Style.BRIGHT}{domain}")
        if domain not in seen_domains:
            seen_domains.append(domain)

    # qr=1 means it's an answer (the server replying with an IP)
    elif dns.qr == 1 and packet.haslayer(DNSRR):
        domain = packet[DNSRR].rrname.decode(errors="replace").rstrip(".")
        answer = packet[DNSRR].rdata
        lines.append(f"  {Fore.CYAN}DNS Answer   : {domain} → {Fore.GREEN}{answer}")

    return lines


# ── Stats dashboard ───────────────────────────────────────────

def show_summary():
    """
    Print a full summary of everything we captured.
    This runs when you press Ctrl+C.
    """
    seconds_running = max((datetime.now() - session_start).seconds, 1)
    packets_per_sec = total_packets / seconds_running

    write(f"\n\n{Fore.CYAN}{Style.BRIGHT}{separator('double')}")
    write(f"{Fore.CYAN}{Style.BRIGHT}  📊  CAPTURE SUMMARY")
    write(f"{Fore.CYAN}{Style.BRIGHT}{separator('double')}")

    write(f"\n  {Fore.WHITE}How long we ran   : {Fore.YELLOW}{seconds_running} seconds")
    write(f"  {Fore.WHITE}Packets captured  : {Fore.YELLOW}{Style.BRIGHT}{total_packets}")
    write(f"  {Fore.WHITE}Average speed     : {Fore.YELLOW}{packets_per_sec:.1f} packets/second")
    write(f"  {Fore.WHITE}Filter used       : {Fore.YELLOW}{TRAFFIC_FILTER or 'none — captured everything'}")
    write(f"  {Fore.WHITE}Log saved to      : {Fore.YELLOW}{log_filename}")

    # Show how many of each protocol we saw
    write(f"\n  {Fore.WHITE}{Style.BRIGHT}What protocols did we see?")
    write(separator("single"))
    for proto, count in sorted(protocol_counts.items(),
                                key=lambda x: x[1], reverse=True):
        bar = "█" * min(count, 30)
        percent = (count / total_packets * 100) if total_packets else 0
        write(f"  {Fore.CYAN}{proto:<8}{Fore.WHITE}{count:>5} packets  "
              f"{Fore.GREEN}{bar} {Fore.YELLOW}{percent:.1f}%")

    # Show which apps generated the most traffic
    if app_counts:
        write(f"\n  {Fore.WHITE}{Style.BRIGHT}Which apps were most active?")
        write(separator("single"))
        for app, count in sorted(app_counts.items(),
                                  key=lambda x: x[1], reverse=True)[:8]:
            write(f"  {Fore.MAGENTA}{app:<18}{Fore.WHITE}{count:>4} packets")

    # Show which IPs sent the most traffic
    if talker_counts:
        write(f"\n  {Fore.WHITE}{Style.BRIGHT}Who was talking the most?")
        write(separator("single"))
        for ip, count in sorted(talker_counts.items(),
                                  key=lambda x: x[1], reverse=True)[:6]:
            write(f"  {Fore.GREEN}{ip:<24}{Fore.WHITE}{count:>4} packets")

    # Show every domain name we spotted
    if seen_domains:
        write(f"\n  {Fore.WHITE}{Style.BRIGHT}Domains your PC contacted ({len(seen_domains)} unique):")
        write(separator("single"))
        for domain in seen_domains:
            write(f"  {Fore.CYAN}⬡  {domain}")

    write(f"\n{Fore.CYAN}{Style.BRIGHT}{separator('double')}\n")
    log_file.close()


# ── Handle Ctrl+C cleanly ─────────────────────────────────────

def on_exit(signal_received, frame):
    """
    When the user presses Ctrl+C, show the summary
    instead of crashing with an ugly error message.
    """
    show_summary()
    sys.exit(0)

signal.signal(signal.SIGINT,  on_exit)
signal.signal(signal.SIGTERM, on_exit)


# ── The main packet handler ───────────────────────────────────

def handle_packet(packet):
    """
    This function runs once for every packet we capture.
    We figure out what type it is, pull out the useful info,
    and print it in a readable format.
    """
    global total_packets
    total_packets += 1
    captured_at = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # Skip packets that don't have an IP header
    # (things like ARP, Ethernet broadcasts, etc.)
    if not packet.haslayer(IP):
        protocol_counts["Other"] += 1
        return

    ip_layer = packet[IP]
    source_ip      = ip_layer.src
    destination_ip = ip_layer.dst
    ttl            = ip_layer.ttl

    # Count this IP as a "talker"
    talker_counts[source_ip] += 1

    protocol_label = ""
    details        = []

    # ── Is it TCP? ────────────────────────────────────────────
    # TCP is used for things like websites, emails, and SSH.
    # It's reliable — every packet is acknowledged.
    if packet.haslayer(TCP):
        tcp  = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        app  = get_app_name(src_port, dst_port)
        flags = str(tcp.flags)

        protocol_counts["TCP"] += 1
        app_counts[app]        += 1
        protocol_label = f"TCP  [{Fore.CYAN}{app}{Fore.WHITE}]"

        details.append(f"  {Fore.YELLOW}Ports    : {src_port} → {dst_port}")
        details.append(f"  {Fore.YELLOW}Flags    : {flags}  ({explain_flags(flags)})")

        # Show payload — but for HTTPS just tell them it's encrypted
        if packet.haslayer(Raw):
            payload_size = len(packet[Raw].load)
            if app in ("HTTPS", "HTTPS-Alt"):
                details.append(
                    f"  {Fore.WHITE}Payload  : "
                    f"[TLS encrypted — {payload_size} bytes]"
                )
            else:
                payload = read_payload(packet)
                if payload:
                    details.append(f"  {Fore.GREEN}Payload  : {payload}")

    # ── Is it UDP? ────────────────────────────────────────────
    # UDP is used for things like DNS, video calls, and gaming.
    # It's fast but doesn't guarantee delivery.
    elif packet.haslayer(UDP):
        udp  = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        app  = get_app_name(src_port, dst_port)

        protocol_counts["UDP"] += 1
        app_counts[app]        += 1
        protocol_label = f"UDP  [{Fore.CYAN}{app}{Fore.WHITE}]"

        details.append(f"  {Fore.YELLOW}Ports    : {src_port} → {dst_port}")

        # Try to read DNS data if it's a DNS packet
        dns_details = read_dns(packet)
        details.extend(dns_details)

        # If it's not DNS, try to show the raw payload
        if not dns_details:
            payload = read_payload(packet)
            if payload:
                details.append(f"  {Fore.GREEN}Payload  : {payload}")

    # ── Is it ICMP? ───────────────────────────────────────────
    # ICMP is used for ping and network error messages.
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_types = {
            0:  "Echo Reply (ping response)",
            3:  "Destination Unreachable",
            8:  "Echo Request (ping)",
            11: "Time Exceeded (TTL expired)",
        }
        description = icmp_types.get(icmp.type, f"Type {icmp.type}")
        protocol_counts["ICMP"] += 1
        app_counts["ICMP"]      += 1
        protocol_label = f"ICMP [{Fore.CYAN}{description}{Fore.WHITE}]"

    # ── Something else ────────────────────────────────────────
    else:
        protocol_counts["Other"] += 1
        protocol_label = f"OTHER (IP protocol number {ip_layer.proto})"

    # ── Print the packet info ─────────────────────────────────
    write(f"\n{separator('double')}")
    write(
        f"  {Fore.MAGENTA}#{total_packets:<5}"
        f"{Fore.WHITE}{captured_at}  "
        f"{Style.BRIGHT}{Fore.WHITE}{protocol_label}"
    )
    write(separator("single"))
    write(f"  {Fore.WHITE}From     : {Fore.GREEN}{source_ip}")
    write(f"  {Fore.WHITE}To       : {Fore.RED}{destination_ip}")
    write(f"  {Fore.WHITE}TTL      : {ttl}  "
          f"{Fore.WHITE}(hops remaining before packet is dropped)")
    for detail in details:
        if detail:
            write(detail)



if __name__ == "__main__":

    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║              Basic Network Sniffer — Final           ║")
    print("  ║     Packet Capture, Analysis & Protocol Decoder      ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print(f"\n  {Fore.YELLOW}Started    : {session_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {Fore.YELLOW}Interface  : Wi-Fi (172.20.10.5)")
    print(f"  {Fore.YELLOW}Filter     : {TRAFFIC_FILTER or 'none — capturing all traffic'}")
    print(f"  {Fore.YELLOW}Log file   : {log_filename}")
    print(f"  {Fore.YELLOW}Tip        : Press Ctrl+C anytime to stop and see your summary\n")

  
    sniff(
        iface=MY_WIFI_INTERFACE,
        filter=TRAFFIC_FILTER,
        prn=handle_packet,
        count=0,     
        store=False  
    )
