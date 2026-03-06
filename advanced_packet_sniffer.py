import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import time
from datetime import datetime
from collections import defaultdict, deque
import json
import csv
from scapy.all import sniff, wrpcap, rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw, get_if_list, conf
from scapy.layers.http import HTTPRequest, HTTPResponse
from port_database import get_port_info, get_protocol_name, is_suspicious_port
import os
import re
from urllib.parse import urlparse

class PacketParser:
    """
    Enhanced packet parser with comprehensive port recognition
    """
    
    @staticmethod

    def get_hex_dump(data):   # ← ADD THIS RIGHT AFTER parse_packet
        """Generate hex dump of binary data"""
        if not data:
            return "No data available"
        
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(48)
            ascii_part = ''.join(
                chr(b) if 32 <= b < 127 else '.' 
                for b in chunk
            )
            result.append(f'{i:04x}  {hex_part}  {ascii_part}')
        
        return '\n'.join(result)

    @staticmethod
    def parse_packet(packet):
        """
        Extract detailed information from a packet with port-based protocol detection
        """
        packet_info = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'length': len(packet),
            'protocol': 'Unknown',
            'src': 'N/A',
            'dst': 'N/A',
            'src_port': None,
            'dst_port': None,
            'info': '',
            'raw_packet': packet,
            'service': None,  # NEW: Service name from port
            'suspicious': False,  # NEW: Suspicious flag
            'flags': '',     # ← ADD THIS
            'payload': b''
        }
        
        # Check if packet has IP layer (IPv4 or IPv6)
        if packet.haslayer(IP):
            packet_info['src'] = packet[IP].src
            packet_info['dst'] = packet[IP].dst
        elif packet.haslayer(IPv6):
            packet_info['src'] = packet[IPv6].src
            packet_info['dst'] = packet[IPv6].dst
        else:
            # No IP layer, return early
            return packet_info

        # Now check transport layer protocols
        # Continue with rest of parsing
        # TCP Protocol
        if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)  # ← ADD THIS
                if packet.haslayer(Raw):                       # ← ADD THIS
                    packet_info['payload'] = packet[Raw].load  # ← ADD THIS
                
                # Determine protocol by port - ENHANCED!
                protocol_detected = False
                
                # Check destination port first (usually the service port)
                port_info = get_port_info(packet[TCP].dport)
                if port_info['protocol'] not in ['REGISTERED', 'DYNAMIC/EPHEMERAL', 'UNKNOWN']:
                    packet_info['protocol'] = port_info['protocol']
                    packet_info['service'] = port_info['description']
                    packet_info['suspicious'] = port_info.get('suspicious', False)
                    packet_info['info'] = f"[{packet[TCP].flags}] {packet[TCP].sport} → {packet[TCP].dport} ({port_info['protocol']})"
                    protocol_detected = True
                
                # If destination port is dynamic, check source port
                elif packet[TCP].sport < 1024:
                    port_info = get_port_info(packet[TCP].sport)
                    if port_info['protocol'] not in ['REGISTERED', 'DYNAMIC/EPHEMERAL', 'UNKNOWN']:
                        packet_info['protocol'] = port_info['protocol']
                        packet_info['service'] = port_info['description']
                        packet_info['suspicious'] = port_info.get('suspicious', False)
                        packet_info['info'] = f"[{packet[TCP].flags}] {packet[TCP].sport} → {packet[TCP].dport} ({port_info['protocol']})"
                        protocol_detected = True
                
                # HTTP Detection (keep existing logic for payload inspection)
                if not protocol_detected:
                    try:
                        if packet.haslayer(HTTPRequest):
                            packet_info['protocol'] = 'HTTP'
                            http = packet[HTTPRequest]
                            method = http.Method.decode('utf-8', errors='ignore') if http.Method else 'GET'
                            host = http.Host.decode('utf-8', errors='ignore') if http.Host else ''
                            path = http.Path.decode('utf-8', errors='ignore') if http.Path else '/'
                            packet_info['info'] = f"{method} {host}{path}"
                            packet_info['service'] = 'Web traffic'
                            protocol_detected = True
                        elif packet.haslayer(HTTPResponse):
                            packet_info['protocol'] = 'HTTP'
                            packet_info['info'] = "HTTP Response"
                            packet_info['service'] = 'Web traffic'
                            protocol_detected = True
                    except Exception:
                        pass
                
                # If still not detected, show as TCP with port info
                if not protocol_detected:
                    packet_info['info'] = f"[{packet[TCP].flags}] {packet[TCP].sport} → {packet[TCP].dport}"
            
            # UDP Protocol
        elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
                # Check for known UDP services by port
                port_info = get_port_info(packet[UDP].dport)
                if port_info['protocol'] not in ['REGISTERED', 'DYNAMIC/EPHEMERAL', 'UNKNOWN']:
                    packet_info['protocol'] = port_info['protocol']
                    packet_info['service'] = port_info['description']
                    packet_info['suspicious'] = port_info.get('suspicious', False)
                    packet_info['info'] = f"{packet[UDP].sport} → {packet[UDP].dport} ({port_info['protocol']})"
                else:
                    # Check source port if dest is dynamic
                    port_info = get_port_info(packet[UDP].sport)
                    if port_info['protocol'] not in ['REGISTERED', 'DYNAMIC/EPHEMERAL', 'UNKNOWN']:
                        packet_info['protocol'] = port_info['protocol']
                        packet_info['service'] = port_info['description']
                        packet_info['info'] = f"{packet[UDP].sport} → {packet[UDP].dport} ({port_info['protocol']})"
                    else:
                        packet_info['info'] = f"{packet[UDP].sport} → {packet[UDP].dport}"
                
                # DNS Detection (keep for detailed query info)
                try:
                    if packet.haslayer(DNS):
                        packet_info['protocol'] = 'DNS'
                        packet_info['service'] = 'Domain name resolution'
                        dns = packet[DNS]
                        
                        if dns.qd is not None and dns.qd.qname:
                            try:
                                query_name = dns.qd.qname.decode('utf-8', errors='ignore')
                                packet_info['info'] = f"Query: {query_name}"
                            except Exception:
                                packet_info['info'] = "DNS Query"
                        elif dns.an is not None:
                            packet_info['info'] = "DNS Response"
                        else:
                            packet_info['info'] = "DNS"
                except Exception:
                    # Fallback to port-based DNS detection
                    if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                        packet_info['protocol'] = 'DNS'
                        packet_info['service'] = 'Domain name resolution'
                        packet_info['info'] = "DNS"
            
            # ICMP Protocol
        elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['service'] = 'Network diagnostics'
                try:
                    icmp_type = packet[ICMP].type
                    if icmp_type == 8:
                        packet_info['info'] = "Echo Request (Ping)"
                    elif icmp_type == 0:
                        packet_info['info'] = "Echo Reply (Pong)"
                    elif icmp_type == 3:
                        packet_info['info'] = "Destination Unreachable"
                    elif icmp_type == 11:
                        packet_info['info'] = "Time Exceeded"
                    else:
                        packet_info['info'] = f"Type {icmp_type}"
                except Exception:
                    packet_info['info'] = "ICMP"
        
        return packet_info

class PacketFilter:
    """Advanced filtering with multiple criteria"""
    
    @staticmethod
    def matches_filter(packet_info, filters):
        """Check if packet matches all active filters"""
        
        # Protocol filter
        if filters.get('protocol') and filters['protocol'] != 'All':
            if packet_info['protocol'] != filters['protocol']:
                return False
        
        # Source IP filter
        if filters.get('src_ip'):
            if filters['src_ip'] not in packet_info['src']:
                return False
        
        # Destination IP filter
        if filters.get('dst_ip'):
            if filters['dst_ip'] not in packet_info['dst']:
                return False
        
        # Port filter
        if filters.get('port'):
            try:
                port = int(filters['port'])
                if packet_info['src_port'] != port and packet_info['dst_port'] != port:
                    return False
            except (ValueError, TypeError):
                pass
        
        # Search term filter
        if filters.get('search_term'):
            search_term = filters['search_term'].lower()
            searchable = f"{packet_info['src']} {packet_info['dst']} {packet_info['info']} {packet_info['protocol']}".lower()
            if search_term not in searchable:
                return False
        
        # Suspicious only filter
        if filters.get('suspicious_only'):
            if not packet_info.get('suspicious', False):
                return False
        
        return True

class PacketStorage:
    """Enhanced storage with statistics and analysis"""
    
    def __init__(self):
        self.packets = []
        self.protocol_count = defaultdict(int)
        self.ip_conversations = defaultdict(int)
        self.bandwidth_history = deque(maxlen=60)  # Last 60 seconds
        self.total_bytes = 0
        self.start_time = time.time()
        self.suspicious_count = 0
        
    
    def add_packet(self, packet_info):
        """Add packet and update statistics"""
        self.packets.append(packet_info)
        
        # Update protocol statistics
        protocol = packet_info['protocol']
        self.protocol_count[protocol] += 1
        
        # Track conversations
        if packet_info['src'] != 'N/A' and packet_info['dst'] != 'N/A':
            conversation = tuple(sorted([packet_info['src'], packet_info['dst']]))
            self.ip_conversations[conversation] += 1
        
        # Update bandwidth
        self.total_bytes += packet_info['length']
        
        # Track suspicious packets
        if packet_info.get('suspicious', False):
            self.suspicious_count += 1
    
    def get_all_packets(self):
        """Retrieve all packets"""
        return self.packets
    
    def get_packet_count(self):
        """Get total number of packets"""
        return len(self.packets)
    
    def clear(self):
        """Clear all stored packets"""
        self.packets.clear()
        self.protocol_count.clear()
        self.ip_conversations.clear()
        self.bandwidth_history.clear()
        self.total_bytes = 0
        self.start_time = time.time()
        self.suspicious_count = 0
    
    def get_statistics(self):
        """Get comprehensive statistics"""
        elapsed_time = time.time() - self.start_time
        
        return {
            'total_packets': len(self.packets),
            'protocol_distribution': dict(self.protocol_count),
            'total_bytes': self.total_bytes,
            'average_packet_size': self.total_bytes / len(self.packets) if self.packets else 0,
            'packets_per_second': len(self.packets) / elapsed_time if elapsed_time > 0 else 0,
            'top_conversations': sorted(self.ip_conversations.items(), key=lambda x: x[1], reverse=True)[:10],
            'suspicious_count': self.suspicious_count
        }
    
    def search_packets(self, search_term):
        """Search packets by term"""
        search_term = search_term.lower()
        results = []
        
        for idx, packet in enumerate(self.packets):
            searchable = f"{packet['src']} {packet['dst']} {packet['info']} {packet['protocol']}".lower()
            if search_term in searchable:
                results.append((idx, packet))
        
        return results
    
    def get_tcp_stream(self, src_ip, dst_ip, src_port, dst_port):
        """Get all packets in a TCP conversation"""
        stream = []
        
        for packet in self.packets:
            if packet['protocol'] in ['TCP', 'HTTP', 'HTTPS', 'SSH',
                                    'FTP', 'SMTP', 'SMTPS', 'IMAP',
                                    'IMAPS', 'POP3', 'POP3S']:  # ← ADD ALL TCP PROTOCOLS
                # Check if packet is part of this conversation
                if ((packet['src'] == src_ip and packet['dst'] == dst_ip and 
                     packet['src_port'] == src_port and packet['dst_port'] == dst_port) or
                    (packet['src'] == dst_ip and packet['dst'] == src_ip and 
                     packet['src_port'] == dst_port and packet['dst_port'] == src_port)):
                    stream.append(packet)
        
        return stream

class AlertSystem:
    """Monitors for suspicious network activity"""
    
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.packet_rate = deque(maxlen=10)
        self.last_alert_time = {}
        self.alert_cooldown = 5  # Seconds between same alert
    
    def check_packet(self, packet_info):
        """Check packet for suspicious activity"""
        alerts = []
        current_time = time.time()
        
        # Check for suspicious ports
        if packet_info.get('suspicious', False):
            alert_key = f"suspicious_port_{packet_info['dst_port']}"
            if self._should_alert(alert_key, current_time):
                alerts.append(f"⚠️ Suspicious port detected: {packet_info['dst_port']}")
        
        # Check for potential port scan (many different ports from same source)
        if packet_info['protocol'] == 'TCP':
            alert_key = f"port_scan_{packet_info['src']}"
            if self._should_alert(alert_key, current_time):
                # This is simplified - real detection would track multiple ports
                pass
        
        # Send alerts
        for alert in alerts:
            self.alert_callback(alert, packet_info)
    
    def _should_alert(self, alert_key, current_time):
        """Check if enough time has passed since last alert"""
        if alert_key not in self.last_alert_time:
            self.last_alert_time[alert_key] = current_time
            return True
        
        if current_time - self.last_alert_time[alert_key] > self.alert_cooldown:
            self.last_alert_time[alert_key] = current_time
            return True
        
        return False

class PacketSniffer:
    """Enhanced packet sniffer with interface selection"""
    
    def __init__(self, packet_queue, alert_system, interface=None):
        self.packet_queue = packet_queue
        self.alert_system = alert_system
        self.interface = interface
        self.active_filters = {}
        self.is_running = False
        self.sniffer_thread = None
    
    def packet_handler(self, packet):
        """Callback for each captured packet"""
        packet_info = PacketParser.parse_packet(packet)
        
        # Check against filters
        if PacketFilter.matches_filter(packet_info, self.active_filters):
            self.packet_queue.put(packet_info)
            
            # Check for alerts
            self.alert_system.check_packet(packet_info)
    
    def start_sniffing(self):
        """Start packet capture"""
        if not self.is_running:
            self.is_running = True
            self.sniffer_thread = threading.Thread(target=self._sniff, daemon=True)
            self.sniffer_thread.start()
    
    def _sniff(self):
        """Internal sniffing method"""
        try:
            # If interface is None, don't specify it - let scapy use default behavior
            if self.interface:
                sniff(
                    iface=self.interface,
                    prn=self.packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.is_running
                )
            else:
                # Capture on all interfaces
                sniff(
                    prn=self.packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.is_running
                )
        except Exception as e:
            self.packet_queue.put({'error': str(e)})
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_running = False
    
    def update_filters(self, filters):
        """Update active filters"""
        self.active_filters = filters
    
    @staticmethod
    def get_available_interfaces():
        """Get list of network interfaces"""
        try:
            return get_if_list()
        except:
            return ['Any']

class StatisticsWindow:
    """Separate window for statistics and graphs"""
    
    def __init__(self, parent, storage):
        self.window = tk.Toplevel(parent)
        self.window.title("Statistics Dashboard")
        self.window.geometry("800x600")
        self.storage = storage
        
        self.setup_gui()
        self.update_statistics()
    
    def setup_gui(self):
        """Setup statistics display"""
        
        # Statistics text area
        self.stats_text = scrolledtext.ScrolledText(self.window, wrap=tk.WORD, height=30)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Refresh button
        refresh_btn = ttk.Button(self.window, text="🔄 Refresh", command=self.update_statistics)
        refresh_btn.pack(pady=5)
    
    def update_statistics(self):
        """Update statistics display"""
        stats = self.storage.get_statistics()
        
        self.stats_text.delete(1.0, tk.END)
        
        output = f"""
{'='*70}
NETWORK TRAFFIC STATISTICS
{'='*70}

GENERAL STATISTICS
{'─'*70}
Total Packets Captured:     {stats['total_packets']:,}
Total Bytes:                {stats['total_bytes']:,} bytes ({stats['total_bytes']/1024/1024:.2f} MB)
Average Packet Size:        {stats['average_packet_size']:.2f} bytes
Packets per Second:         {stats['packets_per_second']:.2f}
Suspicious Packets:         {stats['suspicious_count']}

PROTOCOL DISTRIBUTION
{'─'*70}
"""
        
        # Protocol distribution
        for protocol, count in sorted(stats['protocol_distribution'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
            bar = '█' * int(percentage / 2)
            output += f"{protocol:15} {count:6} packets  [{percentage:5.1f}%] {bar}\n"
        
        output += f"\n{'─'*70}\nTOP CONVERSATIONS (IP Pairs)\n{'─'*70}\n"
        
        # Top conversations
        for idx, (conversation, count) in enumerate(stats['top_conversations'][:10], 1):
            output += f"{idx:2}. {conversation[0]:15} ↔ {conversation[1]:15}  ({count} packets)\n"
        
        self.stats_text.insert(tk.END, output)

class ExportObjectsWindow:
    """Extract and save files from HTTP traffic - like Wireshark"""
    
    def __init__(self, parent, packet_storage):
        self.window = tk.Toplevel(parent)
        self.window.title("Export Objects - HTTP/SMB/TFTP")
        self.window.geometry("900x500")
        self.packet_storage = packet_storage
        self.objects = []
        
        self.setup_gui()
        self.scan_packets()
    
    def setup_gui(self):
        """Setup export objects GUI"""
        
        # Top info bar
        info_frame = ttk.Frame(self.window, padding="10")
        info_frame.pack(fill=tk.X)
        
        self.info_label = ttk.Label(
            info_frame, 
            text="Scanning packets for HTTP objects...",
            font=('Arial', 10, 'bold')
        )
        self.info_label.pack(side=tk.LEFT)
        
        ttk.Button(
            info_frame, text="🔄 Rescan",
            command=self.scan_packets
        ).pack(side=tk.RIGHT)
        
        # Object list table
        list_frame = ttk.Frame(self.window, padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ('No', 'Hostname', 'Filename', 'Content Type', 'Size')
        self.object_tree = ttk.Treeview(
            list_frame, columns=columns, 
            show='headings', height=15
        )
        
        # Column headings
        self.object_tree.heading('No', text='No')
        self.object_tree.heading('Hostname', text='Hostname')
        self.object_tree.heading('Filename', text='Filename')
        self.object_tree.heading('Content Type', text='Content Type')
        self.object_tree.heading('Size', text='Size')
        
        # Column widths
        self.object_tree.column('No', width=50)
        self.object_tree.column('Hostname', width=200)
        self.object_tree.column('Filename', width=250)
        self.object_tree.column('Content Type', width=150)
        self.object_tree.column('Size', width=100)
        
        # Scrollbar
        vsb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, 
                            command=self.object_tree.yview)
        self.object_tree.configure(yscrollcommand=vsb.set)
        self.object_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        btn_frame = ttk.Frame(self.window, padding="10")
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(
            btn_frame, text="💾 Save Selected",
            command=self.save_selected
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, text="💾 Save All",
            command=self.save_all
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, text="❌ Close",
            command=self.window.destroy
        ).pack(side=tk.RIGHT, padx=5)
    
    def scan_packets(self):
        """Scan packets for HTTP objects"""
        self.objects = []
        self.info_label.config(text="Scanning...")
        self.window.update()
        
        # Clear tree
        for item in self.object_tree.get_children():
            self.object_tree.delete(item)
        
        packets = self.packet_storage.get_all_packets()
        
        for packet in packets:
            # Check HTTP, SMB, TFTP packets
            is_exportable = (
                packet['protocol'] in ['HTTP', 'SMB', 'TFTP', 'NETBIOS-SSN'] or
                packet.get('dst_port') in [80, 445, 139, 69] or  # HTTP, SMB, NetBIOS, TFTP
                packet.get('src_port') in [80, 445, 139, 69]
            )
            if not is_exportable:
                continue
            
            try:
                raw = packet['raw_packet']
                if not raw.haslayer(Raw):
                    continue
                
                
                payload = raw[Raw].load
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # Must have HTTP response marker
                if 'HTTP/' not in payload_str:
                    continue
                
                
                # Content-Type might be in this packet OR we detect HTML
                content_type = ''
                
                # Check for Content-Type header
                if 'content-type:' in payload_str.lower():
                    for line in payload_str.split('\r\n'):
                        if line.lower().startswith('content-type:'):
                            content_type = line.split(':', 1)[1].strip().split(';')[0].strip().lower()
                            break
            
                # If no Content-Type but has HTML - assume text/html
                # If no Content-Type but has HTML content - assume text/html
                if not content_type and any(tag in payload_str.lower() for tag in [
                    '<html', '</html>', '<body', '</body>', 
                    '<head', '<div', '<p>', '</p>', '<h1', '<h2'
                ]):
                    content_type = 'text/html'
                    body = payload_str  # Entire payload is the body
                
                # If no Content-Type at all - skip
                if not content_type:
                    continue
                
                # Get body - everything after headers
                body = ''
                if '\r\n\r\n' in payload_str:
                    _, body = payload_str.split('\r\n\r\n', 1)
                else:
                    body = payload_str  # Entire payload is body
                
                if not body.strip():
                    continue
                
                # Extension map
                ext_map = {
                    'text/html': '.html',
                    'text/css': '.css',
                    'text/plain': '.txt',
                    'application/javascript': '.js',
                    'application/json': '.json',
                    'application/pdf': '.pdf',
                    'application/zip': '.zip',
                    'image/jpeg': '.jpg',
                    'image/png': '.png',
                    'image/gif': '.gif',
                    'image/webp': '.webp',
                }
                
                ext = ext_map.get(content_type, '.bin')
                filename = f"object_{len(self.objects) + 1}{ext}"
                hostname = packet['dst']
                body_bytes = body.encode('utf-8', errors='ignore')
                size = len(body_bytes)
                
                if size < 10:
                    continue
                
                obj = {
                    'hostname': hostname,
                    'filename': filename,
                    'content_type': content_type,
                    'size': size,
                    'data': body_bytes
                }
                
                self.objects.append(obj)
                
                if size < 1024:
                    size_str = f"{size} B"
                elif size < 1024 * 1024:
                    size_str = f"{size/1024:.1f} KB"
                else:
                    size_str = f"{size/1024/1024:.1f} MB"
                
                self.object_tree.insert('', 'end', values=(
                    len(self.objects),
                    hostname,
                    filename,
                    content_type,
                    size_str
                ))
            
            except Exception as e:
                continue
           
        count = len(self.objects)
        if count == 0:
            self.info_label.config(
                text="No HTTP objects found. Try capturing HTTP (not HTTPS) traffic!"
            )
        else:
            self.info_label.config(text=f"Found {count} exportable objects!")
        
    def save_selected(self):
            """Save selected object to file"""
            selected = self.object_tree.selection()
            if not selected:
                messagebox.showinfo("No Selection", "Please select an object first!")
                return
            
            idx = self.object_tree.index(selected[0])
            obj = self.objects[idx]
            
            filepath = filedialog.asksaveasfilename(
                initialfile=obj['filename'],
                defaultextension=os.path.splitext(obj['filename'])[1],
                filetypes=[("All files", "*.*")]
            )
            
            if filepath:
                try:
                    with open(filepath, 'wb') as f:
                        f.write(obj['data'])
                    messagebox.showinfo("Success", f"Saved to:\n{filepath}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save:\n{str(e)}")        
        
    def save_all(self):
            """Save all objects to folder"""
            if not self.objects:
                messagebox.showinfo("No Objects", "No objects to save!")
                return
            
            folder = filedialog.askdirectory(title="Select folder to save objects")
            if not folder:
                return
            
            saved = 0
            for obj in self.objects:
                try:
                    filepath = os.path.join(folder, obj['filename'])
                    # Avoid overwriting
                    base, ext = os.path.splitext(filepath)
                    counter = 1
                    while os.path.exists(filepath):
                        filepath = f"{base}_{counter}{ext}"
                        counter += 1
                    
                    with open(filepath, 'wb') as f:
                        f.write(obj['data'])
                    saved += 1
                except Exception:
                    continue
            
            messagebox.showinfo(
                "Success", 
                f"Saved {saved}/{len(self.objects)} objects to:\n{folder}"
            )

class StreamFollowerWindow:
    """Wireshark-style TCP stream follower with navigation"""
    
    def __init__(self, parent, packet_storage, selected_packet):
        self.window = tk.Toplevel(parent)
        self.window.title("Follow TCP Stream")
        self.window.geometry("1000x700")
        self.packet_storage = packet_storage
        self.selected_packet = selected_packet
        self.all_streams = []
        self.current_stream_idx = 0
        
        self.setup_gui()
        self.find_all_streams()
        self.show_current_stream()
    
    def setup_gui(self):
        """Setup stream follower GUI"""
        
        # Top navigation bar
        nav_frame = ttk.Frame(self.window, padding="5")
        nav_frame.pack(fill=tk.X)
        
        ttk.Label(nav_frame, text="Stream:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        
        self.prev_btn = ttk.Button(
            nav_frame, text="◀ Previous",
            command=self.prev_stream
        )
        self.prev_btn.pack(side=tk.LEFT, padx=2)
        
        self.stream_label = ttk.Label(
            nav_frame, text="Stream 0 of 0",
            font=('Arial', 10)
        )
        self.stream_label.pack(side=tk.LEFT, padx=10)
        
        self.next_btn = ttk.Button(
            nav_frame, text="Next ▶",
            command=self.next_stream
        )
        self.next_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(nav_frame, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10
        )
        
        # Stream info label
        self.info_label = ttk.Label(
            nav_frame, text="",
            font=('Arial', 9), foreground="blue"
        )
        self.info_label.pack(side=tk.LEFT, padx=5)
        
        # View options
        ttk.Label(nav_frame, text="View:").pack(side=tk.RIGHT, padx=5)
        self.view_var = tk.StringVar(value="Both")
        view_combo = ttk.Combobox(
            nav_frame, textvariable=self.view_var,
            values=["Both", "Client Only", "Server Only"],
            state="readonly", width=12
        )
        view_combo.pack(side=tk.RIGHT, padx=2)
        view_combo.bind('<<ComboboxSelected>>', lambda e: self.show_current_stream())
        
        # Stream content
        content_frame = ttk.Frame(self.window, padding="5")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Color legend
        legend_frame = ttk.Frame(content_frame)
        legend_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(
            legend_frame, text="■ Client→Server",
            foreground="#0000FF", font=('Arial', 9, 'bold')
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Label(
            legend_frame, text="■ Server→Client",
            foreground="#FF0000", font=('Arial', 9, 'bold')
        ).pack(side=tk.LEFT, padx=10)
        
        # Stream text with colors
        self.stream_text = scrolledtext.ScrolledText(
            content_frame, 
            wrap=tk.WORD, 
            font=('Courier', 9),
            height=30
        )
        self.stream_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure color tags
        self.stream_text.tag_configure('client', foreground='#0000FF')
        self.stream_text.tag_configure('server', foreground='#FF0000')
        self.stream_text.tag_configure('header', foreground='#008800', 
                                       font=('Courier', 9, 'bold'))
        self.stream_text.tag_configure('separator', foreground='#888888')
        
        # Bottom buttons
        btn_frame = ttk.Frame(self.window, padding="5")
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(
            btn_frame, text="💾 Save Stream",
            command=self.save_stream
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, text="📋 Copy All",
            command=self.copy_stream
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame, text="❌ Close",
            command=self.window.destroy
        ).pack(side=tk.RIGHT, padx=5)
    
    def find_all_streams(self):
        """Find ALL TCP streams in captured packets"""
        self.all_streams = []
        seen_streams = set()
        packets = self.packet_storage.get_all_packets()
        
        for packet in packets:
            if not packet['src_port'] or not packet['dst_port']:
                continue
            # Get the base protocol for stream matching
            tcp_protocols = ['TCP', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP', 
                            'SMTPS', 'IMAP', 'IMAPS', 'POP3', 'POP3S',
                            'HTTP-ALT', 'HTTPS-ALT']

            if packet['protocol'] not in tcp_protocols:
                continue
            
            # Create unique stream key (sorted so A↔B = B↔A)
            stream_key = tuple(sorted([
                f"{packet['src']}:{packet['src_port']}",
                f"{packet['dst']}:{packet['dst_port']}"
            ]))
            
            if stream_key not in seen_streams:
                seen_streams.add(stream_key)
                
                # Get all packets for this stream
                stream_packets = self.packet_storage.get_tcp_stream(
                    packet['src'], packet['dst'],
                    packet['src_port'], packet['dst_port']
                )
                
                if stream_packets:
                    self.all_streams.append({
                        'key': stream_key,
                        'src': packet['src'],
                        'dst': packet['dst'],
                        'src_port': packet['src_port'],
                        'dst_port': packet['dst_port'],
                        'packets': stream_packets,
                        'protocol': packet['protocol']
                    })
        
        # Find which stream contains our selected packet
        if self.selected_packet:
            for idx, stream in enumerate(self.all_streams):
                if (stream['src'] == self.selected_packet['src'] and
                    stream['dst'] == self.selected_packet['dst'] and
                    stream['src_port'] == self.selected_packet['src_port'] and
                    stream['dst_port'] == self.selected_packet['dst_port']):
                    self.current_stream_idx = idx
                    break
    
    def show_current_stream(self):
        """Display current stream with colors"""
        self.stream_text.delete(1.0, tk.END)
        
        if not self.all_streams:
            self.stream_text.insert(tk.END, 
                "No TCP streams found!\n\n"
                "Make sure you have captured TCP/HTTP packets."
            )
            self.stream_label.config(text="No streams found")
            return
        
        stream = self.all_streams[self.current_stream_idx]
        total = len(self.all_streams)
        
        # Update navigation
        self.stream_label.config(
            text=f"Stream {self.current_stream_idx + 1} of {total}"
        )
        self.info_label.config(
            text=f"{stream['src']}:{stream['src_port']} ↔ "
                 f"{stream['dst']}:{stream['dst_port']} "
                 f"({stream['protocol']}) | "
                 f"{len(stream['packets'])} packets"
        )
        
        # Disable buttons at boundaries
        self.prev_btn.config(
            state=tk.NORMAL if self.current_stream_idx > 0 else tk.DISABLED
        )
        self.next_btn.config(
            state=tk.NORMAL if self.current_stream_idx < total - 1 else tk.DISABLED
        )
        
        # Write stream header
        self.stream_text.insert(tk.END, 
            f"{'='*80}\n", 'separator'
        )
        self.stream_text.insert(tk.END,
            f"TCP STREAM {self.current_stream_idx + 1}/{total}\n",
            'header'
        )
        self.stream_text.insert(tk.END,
            f"Protocol:    {stream['protocol']}\n"
            f"Client:      {stream['src']}:{stream['src_port']}\n"
            f"Server:      {stream['dst']}:{stream['dst_port']}\n"
            f"Packets:     {len(stream['packets'])}\n",
            'header'
        )
        self.stream_text.insert(tk.END,
            f"{'='*80}\n\n", 'separator'
        )
        
        # Get view mode
        view_mode = self.view_var.get()
        
        # Write each packet
        for idx, pkt in enumerate(stream['packets'], 1):
            is_client = pkt['src'] == stream['src']
            
            # Skip pure TCP packets when viewing HTTPS/HTTP stream
            if stream['protocol'] in ['HTTPS', 'HTTP']:
                if pkt['protocol'] == 'TCP' and not pkt.get('payload'):
                    continue  # Skip TCP handshake/ACK packets with no data
            
            # Skip based on view mode
            if view_mode == "Client Only" and not is_client:
                continue
            if view_mode == "Server Only" and is_client:
                continue
            
            direction = "→" if is_client else "←"
            tag = 'client' if is_client else 'server'
            role = "CLIENT" if is_client else "SERVER"
            
            # Packet header
            self.stream_text.insert(tk.END,
                f"[{idx}] {pkt['timestamp']} {role} {direction} {pkt['info']}\n",
                tag
            )
            
            # Payload
            payload = pkt.get('payload', b'')
            if payload:
                try:
                    text = payload.decode('utf-8', errors='ignore')
                    if text.strip():
                        # Limit payload display
                        if len(text) > 500:
                            text = text[:500] + "...[truncated]"
                        self.stream_text.insert(tk.END, f"{text}\n", tag)
                except Exception:
                    self.stream_text.insert(
                        tk.END, "[Binary data]\n", 'separator'
                    )
            
            self.stream_text.insert(tk.END, f"{'─'*80}\n", 'separator')
    
    def prev_stream(self):
        """Go to previous stream"""
        if self.current_stream_idx > 0:
            self.current_stream_idx -= 1
            self.show_current_stream()
    
    def next_stream(self):
        """Go to next stream"""
        if self.current_stream_idx < len(self.all_streams) - 1:
            self.current_stream_idx += 1
            self.show_current_stream()
    
    def save_stream(self):
        """Save current stream to file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filepath:
            try:
                content = self.stream_text.get(1.0, tk.END)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Stream saved to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save:\n{str(e)}")
    
    def copy_stream(self):
        """Copy stream content to clipboard"""
        content = self.stream_text.get(1.0, tk.END)
        self.window.clipboard_clear()
        self.window.clipboard_append(content)
        messagebox.showinfo("Copied", "Stream content copied to clipboard!")

class PacketSnifferGUI:
    """Enhanced GUI with all advanced features"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Advanced Packet Sniffer - Professional Edition")
        self.root.geometry("1400x900")
        
        self.MAX_PACKETS = 5000  # ← ADD THIS LINE
        
        # Data structures
        self.packet_queue = queue.Queue()
        self.packet_storage = PacketStorage()
        self.alert_system = AlertSystem(self.show_alert)
        self.sniffer = PacketSniffer(self.packet_queue, self.alert_system)
        
        # GUI state
        self.is_capturing = False
        self.current_filters = {}
        self.color_map = {
        'HTTP': '#90EE90',     # Light green
        'HTTPS': '#98FB98',    # Pale green
        'DNS': '#87CEEB',      # Sky blue
        'TCP': '#FFD700',      # Gold
        'UDP': '#FFA500',      # Orange
        'ICMP': '#FF6347',     # Tomato
        'ARP': '#DDA0DD',      # Plum
        'SSH': '#20B2AA',      # Light Sea Green
        'FTP': '#9370DB',      # Medium Purple
        'SMTP': '#FF69B4',     # Hot Pink
        'IMAP': '#FF1493',     # Deep Pink
        'SMB': '#BA55D3',      # Medium Orchid
        'MYSQL': '#32CD32',    # Lime Green
        'REDIS': '#DC143C',    # Crimson
        'RDP': '#4169E1',      # Royal Blue
        'MONGODB': '#228B22',  # Forest Green
        'WIN-RPC': '#DAA520',  # Goldenrod
        'SSDP': '#B0C4DE',     # Light Steel Blue
        }

        self.sort_reverse = {}
        self.carousel_state = {}
        self.setup_gui()
        self.update_packet_list()
        self.update_bandwidth_monitor()
    

    def setup_gui(self):
        """Setup comprehensive GUI layout"""
        
        # Menu Bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Capture (PCAP)", command=self.save_pcap)
        file_menu.add_command(label="Load Capture (PCAP)", command=self.load_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Export to CSV", command=self.export_csv)
        file_menu.add_command(label="Export to JSON", command=self.export_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # View Menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Statistics Dashboard", command=self.show_statistics)
        view_menu.add_command(label="Clear All", command=self.clear_packets)
        view_menu.add_separator()  # ← ADD THIS
        view_menu.add_command(label="Set Packet Limit", command=self.set_packet_limit)  # ← AND THIS
        
        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Follow TCP Stream", command=self.follow_tcp_stream)
        tools_menu.add_command(label="Export Objects - HTTP", command=self.export_http_objects)  # ← ADD
        tools_menu.add_command(label="Search Packets", command=self.show_search_dialog)
        
        # Main container
        main_container = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Top section (controls + filters)
        top_section = ttk.Frame(main_container)
        main_container.add(top_section, weight=1)
        
        self.setup_control_panel(top_section)
        self.setup_filter_panel(top_section)
        
        # Middle section (packet list)
        middle_section = ttk.Frame(main_container)
        main_container.add(middle_section, weight=6)
        self.setup_packet_list(middle_section)
        
        # Bottom section (details + hex view)
        bottom_section = ttk.Frame(main_container)
        main_container.add(bottom_section, weight=3)
        self.setup_details_panel(bottom_section)
    
    def export_http_objects(self):
        ExportObjectsWindow(self.root, self.packet_storage)


    def setup_control_panel(self, parent):
        """Setup control buttons"""
        control_frame = ttk.Frame(parent, padding="5")
        control_frame.pack(fill=tk.X)
        
        # Capture controls
        self.start_btn = ttk.Button(control_frame, text="▶️ Start", 
                            command=self.start_capture, width=15)
        self.stop_btn = ttk.Button(control_frame, text="⏹️ Stop Capture", 
                                command=self.stop_capture, state=tk.DISABLED, width=15)
        self.clear_btn = ttk.Button(control_frame, text="🗑️ Clear All", 
                                    command=self.clear_packets, width=15)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        
        self.stop_btn = ttk.Button(control_frame, text="⏹ Stop", command=self.stop_capture, state=tk.DISABLED, width=10)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        
        self.clear_btn = ttk.Button(control_frame, text="🗑 Clear", command=self.clear_packets, width=10)
        self.clear_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=2)
        self.interface_var = tk.StringVar()
        interfaces = PacketSniffer.get_available_interfaces()
        # Add "Any" option to capture on all interfaces
        interface_list = ["Any"] + interfaces if interfaces else ["Any"]
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, 
                                           values=interface_list, state="readonly", width=15)
        # Default to "Any" for better compatibility
        self.interface_combo.set("Any")
        self.interface_combo.pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(control_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # Status indicators
        self.status_label = ttk.Label(control_frame, text="● Ready", 
                              foreground="blue", font=('Arial', 10, 'bold'))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.count_label = ttk.Label(control_frame, text="Packets: 0")
        self.count_label.pack(side=tk.LEFT, padx=5)
        
        self.bandwidth_label = ttk.Label(control_frame, text="Bandwidth: 0 KB/s")
        self.bandwidth_label.pack(side=tk.LEFT, padx=5)
        
        self.suspicious_label = ttk.Label(control_frame, text="⚠️ Alerts: 0", foreground="red")
        self.suspicious_label.pack(side=tk.RIGHT, padx=5)
    
    def setup_filter_panel(self, parent):
        """Setup advanced filtering"""
        filter_frame = ttk.LabelFrame(parent, text="Filters", padding="5")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Protocol filter
        ttk.Label(filter_frame, text="Protocol:").grid(row=0, column=0, padx=2, sticky=tk.W)
        self.protocol_var = tk.StringVar(value="All")
        protocol_combo = ttk.Combobox(filter_frame, textvariable=self.protocol_var,
                              values=["All", "TCP", "UDP", "HTTP", "HTTPS", "DNS", 
                                     "ICMP", "SSH", "FTP", "SMTP", "IMAP", "POP3",
                                     "SMB", "MYSQL", "REDIS", "RDP", "MONGODB",
                                     "WIN-RPC", "SSDP", "MDNS"],
                              state="readonly", width=12)
        protocol_combo.grid(row=0, column=1, padx=2)
        
        # Source IP filter
        ttk.Label(filter_frame, text="Source IP:").grid(row=0, column=2, padx=2, sticky=tk.W)
        self.src_ip_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.src_ip_var, width=15).grid(row=0, column=3, padx=2)
        
        # Destination IP filter
        ttk.Label(filter_frame, text="Dest IP:").grid(row=0, column=4, padx=2, sticky=tk.W)
        self.dst_ip_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.dst_ip_var, width=15).grid(row=0, column=5, padx=2)
        
        # Port filter
        ttk.Label(filter_frame, text="Port:").grid(row=0, column=6, padx=2, sticky=tk.W)
        self.port_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.port_var, width=8).grid(row=0, column=7, padx=2)
        
        # Suspicious only checkbox
        self.suspicious_var = tk.BooleanVar()
        ttk.Checkbutton(filter_frame, text="Suspicious Only", 
                       variable=self.suspicious_var).grid(row=0, column=8, padx=5)
        
        # Apply filter button
        ttk.Button(filter_frame, text="Apply Filters", 
                  command=self.apply_filters).grid(row=0, column=9, padx=5)
        
        # Clear filters button
        ttk.Button(filter_frame, text="Clear Filters", 
                  command=self.clear_filters).grid(row=0, column=10, padx=2)
    
    def setup_packet_list(self, parent):
        """Setup packet list with color coding"""
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Search bar
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(search_frame, text="🔍 Quick Search:").pack(side=tk.LEFT, padx=2)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.quick_search())
        ttk.Entry(search_frame, textvariable=self.search_var, width=40).pack(side=tk.LEFT, padx=2)
        
        # Treeview
        columns = ('No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show='tree headings', height=20)
        
        self.packet_tree.heading('#0', text='')
        self.packet_tree.column('#0', width=0, stretch=False)
        
        for col in columns:
            self.packet_tree.heading(col, text=col,
                                command=lambda c=col: self.sort_packets(c))
                
        self.packet_tree.column('No', width=60)
        self.packet_tree.column('Time', width=100)
        self.packet_tree.column('Source', width=150)
        self.packet_tree.column('Destination', width=150)
        self.packet_tree.column('Protocol', width=80)
        self.packet_tree.column('Length', width=80)
        self.packet_tree.column('Info', width=500)
        
        # Scrollbars
        vsb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Pack the widgets instead of grid to avoid geometry manager conflict
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Configure tags for colors
        for protocol, color in self.color_map.items():
            self.packet_tree.tag_configure(protocol, background=color)
        self.packet_tree.tag_configure('suspicious', background='#FF6B6B')
        
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        self.packet_tree.bind('<Double-Button-1>', self.on_double_click)
    
    
    def on_double_click(self, event):
        """Handle double-click only on packet rows, not headers"""
        region = self.packet_tree.identify_region(event.x, event.y)
    
        if region == "cell":
        # Double-clicked on a packet row
            self.follow_tcp_stream()
        # If clicked on heading, ignore (sort will happen from heading command)
    
    def setup_details_panel(self, parent):
        """Setup packet details and hex view"""
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packet Details Tab
        details_frame = ttk.Frame(notebook)
        notebook.add(details_frame, text="Packet Details")
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=12, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Hex View Tab
        hex_frame = ttk.Frame(notebook)
        notebook.add(hex_frame, text="Hex/ASCII View")
        
        self.hex_text = scrolledtext.ScrolledText(hex_frame, height=12, wrap=tk.NONE, 
                                                   font=('Courier', 9))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
    
    def start_capture(self):
        """Start capturing packets"""
        try:
            # Get interface - if empty or "Any", use None to capture on all interfaces
            interface = self.interface_var.get()
            if not interface or interface == "Any" or interface == "":
                interface = None
            
            # Create new sniffer instance with selected interface
            self.sniffer = PacketSniffer(self.packet_queue, self.alert_system, interface)
            self.sniffer.update_filters(self.current_filters)
            
            self.is_capturing = True
            self.sniffer.start_sniffing()
            
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="● Capturing", foreground="green")
            
            self.packet_storage.start_time = time.time()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture:\n{str(e)}\n\nTry running with admin privileges.")
    
    def stop_capture(self):
        """Stop capturing packets"""
        self.is_capturing = False
        self.sniffer.stop_sniffing()
        
        # DRAIN remaining packets in queue
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except:
                break
        
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="● Stopped", foreground="red")
    
    def clear_packets(self):
        """Clear all packets"""
        if messagebox.askyesno("Clear Packets", "Clear all captured packets?"):
            self.packet_storage.clear()
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            self.details_text.delete(1.0, tk.END)
            self.hex_text.delete(1.0, tk.END)
            self.count_label.config(text="Packets: 0")
            self.suspicious_label.config(text="⚠️ Alerts: 0")
    
    def apply_filters(self):
        """Apply current filters"""
        self.current_filters = {
            'protocol': self.protocol_var.get() if self.protocol_var.get() != 'All' else None,
            'src_ip': self.src_ip_var.get() if self.src_ip_var.get() else None,
            'dst_ip': self.dst_ip_var.get() if self.dst_ip_var.get() else None,
            'port': self.port_var.get() if self.port_var.get() else None,
            'suspicious_only': self.suspicious_var.get()
        }
        
        self.sniffer.update_filters(self.current_filters)
        messagebox.showinfo("Filters", "Filters applied successfully!")
    
    def clear_filters(self):
        """Clear all filters"""
        self.protocol_var.set("All")
        self.src_ip_var.set("")
        self.dst_ip_var.set("")
        self.port_var.set("")
        self.suspicious_var.set(False)
        self.current_filters = {}
        self.sniffer.update_filters({})
    

    def set_packet_limit(self):
        """Allow user to change packet limit"""
        from tkinter import simpledialog
        
        new_limit = simpledialog.askinteger(
            "Set Packet Limit",
            "Enter maximum number of packets to capture:\n"
            "(Higher values may slow down the GUI)",
            initialvalue=self.MAX_PACKETS,
            minvalue=100,
            maxvalue=100000
        )
    
        if new_limit:
            self.MAX_PACKETS = new_limit
            messagebox.showinfo("Limit Updated", f"Packet limit set to {new_limit}")

    def quick_search(self):
        """Quick search as you type"""
        search_term = self.search_var.get().lower()
        
        if not search_term:
            # Show all items
            for item in self.packet_tree.get_children():
                self.packet_tree.item(item, tags=self.packet_tree.item(item)['tags'])
            return
        
        # Hide non-matching items
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item)['values']
            searchable = ' '.join(str(v).lower() for v in values)
            
            if search_term in searchable:
                self.packet_tree.item(item, tags=self.packet_tree.item(item)['tags'])
            else:
                # Make semi-transparent (simplified - just show/hide)
                pass
    
    def update_packet_list(self):
            """Update packet list from queue"""
            
            MAX_PER_UPDATE = 10

            try:
                packets_processed = 0
                
                while not self.packet_queue.empty() and packets_processed < MAX_PER_UPDATE:
                    packet_info = self.packet_queue.get_nowait()
                    
                    if 'error' in packet_info:
                        messagebox.showerror("Capture Error", packet_info['error'])
                        self.stop_capture()
                        continue
                    
                    # ✅ CHECK LIMIT BEFORE ADDING
                    current_count = self.packet_storage.get_packet_count()

                    # Temporary debug

                    if current_count >= self.MAX_PACKETS:
                        if self.is_capturing:
                            self.stop_capture()
                            messagebox.showwarning(
                                "Packet Limit Reached", 
                                f"Reached {self.MAX_PACKETS} packets. Capture stopped."
                            )
                        continue
                    
                    # Add packet
                    self.packet_storage.add_packet(packet_info)
                    
                    packet_no = self.packet_storage.get_packet_count()
                    values = (
                        packet_no,
                        packet_info['timestamp'],
                        packet_info['src'],
                        packet_info['dst'],
                        packet_info['protocol'],
                        packet_info['length'],
                        packet_info['info']
                    )
                    
                    # Color coding
                    tags = []
                    if packet_info.get('suspicious', False):
                        tags.append('suspicious')
                    elif packet_info['protocol'] in self.color_map:
                        tags.append(packet_info['protocol'])
                    
                    self.packet_tree.insert('', tk.END, values=values, tags=tags)
                    
                    # Update count label
                    self.count_label.config(text=f"Packets: {packet_no}")
                    
                    # Color warningss
                    if packet_no >= self.MAX_PACKETS:
                        self.count_label.config(foreground="red", font=('Arial', 9, 'bold'))
                    elif packet_no >= self.MAX_PACKETS * 0.8:
                        self.count_label.config(foreground="orange", font=('Arial', 9, 'bold'))
                    elif packet_no >= self.MAX_PACKETS * 0.5:
                        self.count_label.config(foreground="blue")
                    else:
                        self.count_label.config(foreground="black")
                    
                    self.suspicious_label.config(text=f"⚠️ Alerts: {self.packet_storage.suspicious_count}")
                    
                    packets_processed += 1  # ← At the END!
            
            except queue.Empty:
                pass
            
            self.root.after(50, self.update_packet_list)


    def update_bandwidth_monitor(self):
        """Update bandwidth display"""
        if self.is_capturing and self.packet_storage.packets:
            elapsed = time.time() - self.packet_storage.start_time
            if elapsed > 0:
                bytes_per_sec = self.packet_storage.total_bytes / elapsed
                kb_per_sec = bytes_per_sec / 1024
                self.bandwidth_label.config(text=f"Bandwidth: {kb_per_sec:.2f} KB/s")
        
        self.root.after(1000, self.update_bandwidth_monitor)
    
    def on_packet_select(self, event):
        """Display packet details when selected"""
        selected = self.packet_tree.selection()
        if not selected:
            return
        
        item = self.packet_tree.item(selected[0])
        packet_no = int(item['values'][0]) - 1
        
        packets = self.packet_storage.get_all_packets()
        if packet_no < len(packets):
            packet_info = packets[packet_no]
            self.display_packet_details(packet_info)
            self.display_hex_view(packet_info)
    
    def display_packet_details(self, packet_info):
        """Display detailed packet information"""
        self.details_text.delete(1.0, tk.END)
        
        details = f"""
{'='*80}
PACKET DETAILS
{'='*80}

TIMESTAMP:      {packet_info['timestamp']}
PROTOCOL:       {packet_info['protocol']}
LENGTH:         {packet_info['length']} bytes

SOURCE:         {packet_info['src']}
DESTINATION:    {packet_info['dst']}

"""
        
        if packet_info['src_port']:
            details += f"SOURCE PORT:    {packet_info['src_port']}\n"
        if packet_info['dst_port']:
            details += f"DEST PORT:      {packet_info['dst_port']}\n"
        if packet_info.get('flags'):
            details += f"TCP FLAGS:      {packet_info['flags']}\n"
        
        details += f"\nINFO:           {packet_info['info']}\n"
        
        if packet_info.get('suspicious', False):
            details += f"\n⚠️  SUSPICIOUS:   This packet triggered security alerts!\n"
        
        details += f"\n{'-'*80}\nRAW PACKET SUMMARY\n{'-'*80}\n"
        details += packet_info['raw_packet'].summary()
        
        details += f"\n\n{'-'*80}\nLAYER BREAKDOWN\n{'-'*80}\n"
        details += packet_info['raw_packet'].show(dump=True)
        
        self.details_text.insert(tk.END, details)
    
    def display_hex_view(self, packet_info):
        """Display hex dump of packet payload"""
        self.hex_text.delete(1.0, tk.END)
        
        if packet_info.get('payload'):
            hex_dump = PacketParser.get_hex_dump(packet_info['payload'])
            self.hex_text.insert(tk.END, f"Payload ({len(packet_info['payload'])} bytes):\n\n")
            self.hex_text.insert(tk.END, hex_dump)
        else:
            self.hex_text.insert(tk.END, "No payload data available for this packet.")
    
    def show_alert(self, alert_message, packet_info):
        """Display security alert"""
        # Update suspicious count is already done in storage
        # Could add a popup or log window here
        pass
    
    def save_pcap(self):
        """Save packets to PCAP file"""
        if not self.packet_storage.packets:
            messagebox.showwarning("No Data", "No packets to save!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                raw_packets = [p['raw_packet'] for p in self.packet_storage.packets]
                wrpcap(filename, raw_packets)
                messagebox.showinfo("Success", f"Saved {len(raw_packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {str(e)}")
    
    def load_pcap(self):
        """Load packets from PCAP file"""
        filename = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                self.clear_packets()
                packets = rdpcap(filename)
                
                for packet in packets:
                    packet_info = PacketParser.parse_packet(packet)
                    self.packet_storage.add_packet(packet_info)
                    
                    packet_no = self.packet_storage.get_packet_count()
                    values = (
                        packet_no,
                        packet_info['timestamp'],
                        packet_info['src'],
                        packet_info['dst'],
                        packet_info['protocol'],
                        packet_info['length'],
                        packet_info['info']
                    )
                    
                    tags = []
                    if packet_info.get('suspicious', False):
                        tags.append('suspicious')
                    elif packet_info['protocol'] in self.color_map:
                        tags.append(packet_info['protocol'])
                    
                    self.packet_tree.insert('', tk.END, values=values, tags=tags)
                
                self.count_label.config(text=f"Packets: {len(packets)}")
                messagebox.showinfo("Success", f"Loaded {len(packets)} packets from {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load: {str(e)}")
    
    def export_csv(self):
        """Export packets to CSV"""
        if not self.packet_storage.packets:
            messagebox.showwarning("No Data", "No packets to export!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['No', 'Timestamp', 'Source', 'Destination', 
                                   'Protocol', 'Length', 'Info', 'Src Port', 'Dst Port'])
                    
                    for idx, packet in enumerate(self.packet_storage.packets, 1):
                        writer.writerow([
                            idx,
                            packet['timestamp'],
                            packet['src'],
                            packet['dst'],
                            packet['protocol'],
                            packet['length'],
                            packet['info'],
                            packet.get('src_port', 'N/A'),
                            packet.get('dst_port', 'N/A')
                        ])
                
                messagebox.showinfo("Success", f"Exported {len(self.packet_storage.packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def export_json(self):
        """Export packets to JSON"""
        if not self.packet_storage.packets:
            messagebox.showwarning("No Data", "No packets to export!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                export_data = []
                for idx, packet in enumerate(self.packet_storage.packets, 1):
                    export_data.append({
                        'number': idx,
                        'timestamp': packet['timestamp'],
                        'source': packet['src'],
                        'destination': packet['dst'],
                        'protocol': packet['protocol'],
                        'length': packet['length'],
                        'info': packet['info'],
                        'src_port': packet.get('src_port'),
                        'dst_port': packet.get('dst_port'),
                        'suspicious': packet.get('suspicious', False)
                    })
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                messagebox.showinfo("Success", f"Exported {len(export_data)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def show_statistics(self):
        """Show statistics dashboard"""
        StatisticsWindow(self.root, self.packet_storage)
    
    def follow_tcp_stream(self):
        """Follow TCP stream for selected packet - Wireshark style"""
        selected = self.packet_tree.selection()
        if not selected:
            messagebox.showinfo("No Selection", "Please select a packet first!")
            return
        
        item = self.packet_tree.item(selected[0])
        packet_no = int(item['values'][0]) - 1
        packets = self.packet_storage.get_all_packets()
        
        if packet_no < len(packets):
            selected_packet = packets[packet_no]
            StreamFollowerWindow(self.root, self.packet_storage, selected_packet)
    
    def show_search_dialog(self):
        """Show advanced search dialog"""
        search_window = tk.Toplevel(self.root)
        search_window.title("Search Packets")
        search_window.geometry("500x150")
        
        ttk.Label(search_window, text="Search for:").pack(pady=10)
        
        search_entry = ttk.Entry(search_window, width=50)
        search_entry.pack(pady=5)
        search_entry.focus()
        
        result_label = ttk.Label(search_window, text="")
        result_label.pack(pady=10)
        
        def do_search():
            term = search_entry.get()
            if term:
                results = self.packet_storage.search_packets(term)
                result_label.config(text=f"Found {len(results)} matching packets")
                
                # Highlight first result
                if results:
                    idx, _ = results[0]
                    children = self.packet_tree.get_children()
                    if idx < len(children):
                        self.packet_tree.selection_set(children[idx])
                        self.packet_tree.see(children[idx])
        
        ttk.Button(search_window, text="Search", command=do_search).pack(pady=5)
        search_entry.bind('<Return>', lambda e: do_search())

    def sort_packets(self, column):
        """Hybrid sort - Carousel for text columns, Toggle for numeric/time columns"""
        
        # Get column index
        columns_list = ['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
        col_idx = columns_list.index(column)
        
        # Collect ALL items
        all_items = []
        for item_id in self.packet_tree.get_children(''):
            item_data = self.packet_tree.item(item_id)
            all_items.append({
                'values': item_data['values'],
                'tags': item_data['tags']
            })
        
        # Different sorting for different column types
        if column in ['No', 'Time', 'Length']:
            # TOGGLE SORT (ascending/descending)
            
            # Toggle direction
            if column not in self.sort_reverse:
                self.sort_reverse[column] = False
            else:
                self.sort_reverse[column] = not self.sort_reverse[column]
            
            reverse = self.sort_reverse[column]
            
            # Sort numerically or by time
            if column in ['No', 'Length']:
                all_items.sort(
                    key=lambda x: int(x['values'][col_idx]) if str(x['values'][col_idx]).isdigit() else 0,
                    reverse=reverse
                )
            else:  # Time
                all_items.sort(
                    key=lambda x: str(x['values'][col_idx]),
                    reverse=reverse
                )
            
            # Update header with arrow
            arrow = ' ▼' if reverse else ' ▲'
            header_text = column + arrow
        
        else:
            # CAROUSEL SORT (cycle through unique values)
            
            # Get unique values (sorted)
            unique_values = sorted(set(str(item['values'][col_idx]) for item in all_items))
            
            # Initialize or increment carousel position
            if column not in self.carousel_state:
                self.carousel_state[column] = 0
            else:
                self.carousel_state[column] = (self.carousel_state[column] + 1) % len(unique_values)
            
            # Get current featured value
            current_value = unique_values[self.carousel_state[column]]
            
            # Sort: current value first, rest alphabetically
            def sort_key(item):
                value = str(item['values'][col_idx])
                if value == current_value:
                    return (0, value)
                else:
                    return (1, value)
            
            all_items.sort(key=sort_key)
            
            # Update header with featured value
            header_text = f"{column} [{current_value}]"
        
        # Delete ALL items
        for item_id in self.packet_tree.get_children(''):
            self.packet_tree.delete(item_id)
        
        # Re-insert in sorted order
        for item in all_items:
            self.packet_tree.insert('', 'end', values=item['values'], tags=item['tags'])
        
        # Update column headers
        for col in columns_list:
            if col == column:
                self.packet_tree.heading(
                    col, 
                    text=header_text,
                    command=lambda c=col: self.sort_packets(c)
                )
            else:
                self.packet_tree.heading(
                    col,
                    text=col,
                    command=lambda c=col: self.sort_packets(c)
                )

    def export_http_objects(self):
        """Open Export Objects window"""
        ExportObjectsWindow(self.root, self.packet_storage)

class HTTPObjectExtractor:
    """Extract files/objects from HTTP traffic"""
    
    def __init__(self):
        self.objects = []
        
        # Common content types we can extract
        self.content_types = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'image/svg+xml': '.svg',
            'application/pdf': '.pdf',
            'application/zip': '.zip',
            'application/json': '.json',
            'text/html': '.html',
            'text/css': '.css',
            'text/javascript': '.js',
            'application/javascript': '.js',
            'application/octet-stream': '.bin',
            'video/mp4': '.mp4',
            'audio/mpeg': '.mp3',
        }
    
    def extract_objects_from_packets(self, packets):
        """
        Scan all packets and extract HTTP objects
        
        Args:
            packets: List of packet_info dictionaries
        
        Returns:
            List of extractable objects
        """
        self.objects = []
        
        # Group packets into HTTP conversations
        http_streams = self._group_http_streams(packets)
        
        # Extract objects from each stream
        for stream in http_streams:
            self._extract_from_stream(stream)
        
        return self.objects
    
    def _group_http_streams(self, packets):
        """Group HTTP packets into request-response pairs"""
        streams = {}
        
        for packet in packets:
            if packet['protocol'] != 'HTTP':
                continue
            
            # Create stream key (conversation identifier)
            if packet['src_port'] and packet['dst_port']:
                stream_key = f"{packet['src']}:{packet['src_port']}-{packet['dst']}:{packet['dst_port']}"
                
                if stream_key not in streams:
                    streams[stream_key] = []
                
                streams[stream_key].append(packet)
        
        return list(streams.values())
    
    def _extract_from_stream(self, stream):
        """Extract objects from an HTTP stream"""
        
        for packet in stream:
            # Check if packet has raw data
            if not packet.get('raw_packet'):
                continue
            
            try:
                from scapy.all import Raw
                
                if packet['raw_packet'].haslayer(Raw):
                    payload = packet['raw_packet'][Raw].load
                    
                    # Try to parse HTTP response
                    if b'HTTP/' in payload and b'Content-Type:' in payload:
                        self._parse_http_response(payload, packet)
            
            except Exception as e:
                # Skip malformed packets
                continue
    
    def _parse_http_response(self, payload, packet):
        """Parse HTTP response and extract object info"""
        
        try:
            # Convert to string for parsing headers
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Split headers and body
            if '\r\n\r\n' in payload_str:
                headers, body = payload_str.split('\r\n\r\n', 1)
            else:
                return
            
            # Parse headers
            header_lines = headers.split('\r\n')
            
            content_type = None
            content_length = 0
            filename = None
            
            for line in header_lines:
                line_lower = line.lower()
                
                if line_lower.startswith('content-type:'):
                    content_type = line.split(':', 1)[1].strip().split(';')[0]
                
                elif line_lower.startswith('content-length:'):
                    try:
                        content_length = int(line.split(':', 1)[1].strip())
                    except:
                        pass
                
                elif line_lower.startswith('content-disposition:'):
                    # Try to extract filename
                    match = re.search(r'filename[^;=\n]*=(([\'"]).*?\2|[^;\n]*)', line)
                    if match:
                        filename = match.group(1).strip('\'"')
            
            # Check if we can extract this content type
            if content_type in self.content_types:
                
                # Generate filename if not provided
                if not filename:
                    extension = self.content_types.get(content_type, '')
                    filename = f"object_{len(self.objects) + 1}{extension}"
                
                # Calculate actual size
                body_bytes = body.encode('utf-8', errors='ignore')
                actual_size = len(body_bytes)
                
                # Store object info
                obj = {
                    'packet_no': packet.get('No', '?'),
                    'hostname': self._extract_hostname(packet),
                    'content_type': content_type,
                    'size': actual_size if actual_size > 0 else content_length,
                    'filename': filename,
                    'data': body_bytes,
                    'source_ip': packet['src'],
                    'dest_ip': packet['dst'],
                }
                
                self.objects.append(obj)
        
        except Exception as e:
            # Skip if parsing fails
            pass
    
    def _extract_hostname(self, packet):
        """Extract hostname from packet info"""
        info = packet.get('info', '')
        
        # Try to extract from GET/POST request
        if 'GET' in info or 'POST' in info:
            parts = info.split()
            if len(parts) >= 2:
                url = parts[1]
                return url.split('/')[0] if '/' in url else url
        
        return packet['dst']
    
    def save_object(self, obj, output_dir):
        """
        Save an extracted object to disk
        
        Args:
            obj: Object dictionary
            output_dir: Directory to save to
        
        Returns:
            Path to saved file or None
        """
        try:
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            # Sanitize filename
            safe_filename = re.sub(r'[<>:"/\\|?*]', '_', obj['filename'])
            filepath = os.path.join(output_dir, safe_filename)
            
            # Avoid overwriting - add number if file exists
            base, ext = os.path.splitext(filepath)
            counter = 1
            while os.path.exists(filepath):
                filepath = f"{base}_{counter}{ext}"
                counter += 1
            
            # Write data
            with open(filepath, 'wb') as f:
                f.write(obj['data'])
            
            return filepath
        
        except Exception as e:
            return None


def main():
    """Main entry point"""
    root = tk.Tk()
    
    # Permission check
    try:
        import os
        if os.name != 'nt' and os.geteuid() != 0:
            messagebox.showwarning(
                "Permission Warning",
                "This application requires root/administrator privileges for packet capture.\n\n"
                "Linux/Mac: Run with 'sudo python3 advanced_packet_sniffer.py'\n"
                "Windows: Run terminal as Administrator"
            )
    except AttributeError:
        pass
    
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
