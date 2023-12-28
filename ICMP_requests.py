import scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP, TCP
import time

start_time = time.perf_counter()


def send_icmp():
    for i in range(0, 256):
        target_ip = "192.168.1." + str(i)
        print(f"Sending ICMP to {target_ip}")
        ip_packet = IP(dst=str(target_ip)) / ICMP()
        send = sr1(ip_packet, timeout=2, verbose=False)
        if send:
            send.show()
            print(f"Packet {i} was successfully sent at: {start_time}")
            with open("Existing_ip.txt", 'w') as file:
                file.write(target_ip)
        else:
            print(f"Packet {i} timed out at: {start_time}")


if __name__ == "__main__":
    try:
        send_icmp()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
