from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
import sys


def trace_route(destination_ip):
    for ttl in range(1, 30):  # Set a maximum TTL value to prevent infinite loops
        packet = IP(dst=destination_ip, ttl=ttl) / ICMP()
        response = sr1(packet, verbose=False, timeout=2)

        if response is None:
            print(f"{ttl}: *")
        else:
            print(f"{ttl}: {response.src}")

        if response and response.src == destination_ip:
            break


if __name__ == "__main__":
    if len(sys.argv) != 1:
        print("Usage: cc_trace_route ip_address")
        sys.exit(1)
    ip_address = sys.argv
    trace_route(ip_address)
