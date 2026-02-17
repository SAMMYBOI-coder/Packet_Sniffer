# port_database.py
"""
Expanded Port Database for Packet Sniffer
Maps port numbers to protocol names and descriptions
"""

COMMON_PORTS = {
    # Web & HTTP
    80: {'protocol': 'HTTP', 'description': 'Web traffic (unencrypted)'},
    443: {'protocol': 'HTTPS', 'description': 'Secure web traffic (encrypted)'},
    8080: {'protocol': 'HTTP-ALT', 'description': 'Alternative HTTP port'},
    8443: {'protocol': 'HTTPS-ALT', 'description': 'Alternative HTTPS port'},
    8008: {'protocol': 'HTTP-ALT', 'description': 'Alternative HTTP port'},
    8888: {'protocol': 'HTTP-ALT', 'description': 'HTTP alternative / Proxy'},
    4443: {'protocol': 'HTTPS-ALT', 'description': 'Alternative HTTPS port'},
    
    # Email
    25: {'protocol': 'SMTP', 'description': 'Email sending'},
    110: {'protocol': 'POP3', 'description': 'Email retrieval'},
    143: {'protocol': 'IMAP', 'description': 'Email access'},
    465: {'protocol': 'SMTPS', 'description': 'Secure SMTP'},
    587: {'protocol': 'SMTP-SUB', 'description': 'Email submission'},
    993: {'protocol': 'IMAPS', 'description': 'Secure IMAP'},
    995: {'protocol': 'POP3S', 'description': 'Secure POP3'},
    
    # File Transfer
    20: {'protocol': 'FTP-DATA', 'description': 'FTP data transfer'},
    21: {'protocol': 'FTP', 'description': 'File transfer control'},
    22: {'protocol': 'SSH', 'description': 'Secure Shell / SFTP'},
    69: {'protocol': 'TFTP', 'description': 'Trivial file transfer'},
    115: {'protocol': 'SFTP', 'description': 'Simple file transfer'},
    989: {'protocol': 'FTPS-DATA', 'description': 'Secure FTP data'},
    990: {'protocol': 'FTPS', 'description': 'Secure FTP control'},
    
    # DNS & Network
    53: {'protocol': 'DNS', 'description': 'Domain name system'},
    67: {'protocol': 'DHCP-SERVER', 'description': 'DHCP server'},
    68: {'protocol': 'DHCP-CLIENT', 'description': 'DHCP client'},
    
    # Remote Access
    23: {'protocol': 'TELNET', 'description': 'Unencrypted remote login'},
    3389: {'protocol': 'RDP', 'description': 'Remote Desktop Protocol'},
    5900: {'protocol': 'VNC', 'description': 'Virtual Network Computing'},
    5901: {'protocol': 'VNC', 'description': 'VNC display 1'},
    
    # Database
    1433: {'protocol': 'MSSQL', 'description': 'Microsoft SQL Server'},
    1521: {'protocol': 'ORACLE', 'description': 'Oracle Database'},
    3306: {'protocol': 'MYSQL', 'description': 'MySQL Database'},
    5432: {'protocol': 'POSTGRESQL', 'description': 'PostgreSQL Database'},
    27017: {'protocol': 'MONGODB', 'description': 'MongoDB Database'},
    6379: {'protocol': 'REDIS', 'description': 'Redis Database'},
    
    # Messaging
    194: {'protocol': 'IRC', 'description': 'Internet Relay Chat'},
    5222: {'protocol': 'XMPP', 'description': 'Jabber/XMPP messaging'},
    6667: {'protocol': 'IRC', 'description': 'IRC alternative port'},
    
    # VoIP & Streaming
    5060: {'protocol': 'SIP', 'description': 'VoIP signaling'},
    5061: {'protocol': 'SIPS', 'description': 'Secure VoIP signaling'},
    1935: {'protocol': 'RTMP', 'description': 'Real-Time Messaging (streaming)'},
    554: {'protocol': 'RTSP', 'description': 'Real-Time Streaming'},
    
    # Gaming
    25565: {'protocol': 'MINECRAFT', 'description': 'Minecraft game server'},
    27015: {'protocol': 'STEAM', 'description': 'Steam game server'},
    3074: {'protocol': 'XBOX-LIVE', 'description': 'Xbox Live'},
    3478: {'protocol': 'STUN', 'description': 'STUN/TURN (gaming/video)'},
    3479: {'protocol': 'STUN', 'description': 'STUN/TURN (gaming/video)'},
    19132: {'protocol': 'MINECRAFT-PE', 'description': 'Minecraft Pocket Edition'},
    
    # VPN
    1194: {'protocol': 'OPENVPN', 'description': 'OpenVPN'},
    1723: {'protocol': 'PPTP', 'description': 'VPN (PPTP)'},
    3128: {'protocol': 'SQUID', 'description': 'Squid proxy'},
    9050: {'protocol': 'TOR', 'description': 'Tor SOCKS proxy'},
    500: {'protocol': 'ISAKMP', 'description': 'VPN key exchange (IPSec)'},
    4500: {'protocol': 'IPSEC', 'description': 'IPSec NAT traversal'},
    1701: {'protocol': 'L2TP', 'description': 'Layer 2 Tunneling Protocol'},
    
    # Network Services
    123: {'protocol': 'NTP', 'description': 'Network Time Protocol'},
    161: {'protocol': 'SNMP', 'description': 'Network monitoring'},
    162: {'protocol': 'SNMPTRAP', 'description': 'SNMP traps'},
    514: {'protocol': 'SYSLOG', 'description': 'System logging'},
    
    # File Sharing / Windows
    137: {'protocol': 'NETBIOS-NS', 'description': 'NetBIOS Name Service'},
    138: {'protocol': 'NETBIOS-DGM', 'description': 'NetBIOS Datagram'},
    139: {'protocol': 'NETBIOS-SSN', 'description': 'NetBIOS Session'},
    445: {'protocol': 'SMB', 'description': 'Windows file sharing'},
    2049: {'protocol': 'NFS', 'description': 'Network File System'},
    
    # Windows Specific - KEY ADDITIONS!
    135: {'protocol': 'MS-RPC', 'description': 'Microsoft RPC (Windows services)'},
    1900: {'protocol': 'SSDP', 'description': 'UPnP / Device discovery'},
    5353: {'protocol': 'MDNS', 'description': 'Multicast DNS (Apple/Windows)'},
    3702: {'protocol': 'WS-DISCOVERY', 'description': 'Windows Web Services Discovery'},
    5355: {'protocol': 'LLMNR', 'description': 'Link-Local Multicast Name Resolution'},
    2869: {'protocol': 'UPNP', 'description': 'UPnP event notification'},
    
    # Windows Dynamic RPC ports
    49152: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    49153: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    49154: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    49155: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    49156: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    49157: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    49158: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    49159: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    49160: {'protocol': 'WIN-RPC', 'description': 'Windows dynamic RPC'},
    
    # Google Services (commonly seen!)
    5228: {'protocol': 'GOOGLE-PUSH', 'description': 'Google Play / Push notifications'},
    5229: {'protocol': 'GOOGLE-PUSH', 'description': 'Google push notifications'},
    5230: {'protocol': 'GOOGLE-PUSH', 'description': 'Google push notifications'},
    
    # Apple Services
    2195: {'protocol': 'APNS', 'description': 'Apple Push Notification Service'},
    2196: {'protocol': 'APNS', 'description': 'Apple Push feedback'},
    
    # Print Services
    515: {'protocol': 'LPD', 'description': 'Line printer daemon'},
    631: {'protocol': 'IPP', 'description': 'Internet Printing Protocol'},
    9100: {'protocol': 'JET-DIRECT', 'description': 'HP printer'},
    
    # Development
    9000: {'protocol': 'PHP-FPM', 'description': 'PHP FastCGI'},
    5000: {'protocol': 'FLASK', 'description': 'Flask development server'},
    3000: {'protocol': 'NODE-DEV', 'description': 'Node.js / Grafana'},
    8000: {'protocol': 'DJANGO', 'description': 'Django development'},
    4200: {'protocol': 'ANGULAR', 'description': 'Angular development'},
    
    # Monitoring
    9090: {'protocol': 'PROMETHEUS', 'description': 'Prometheus monitoring'},
    9200: {'protocol': 'ELASTICSEARCH', 'description': 'Elasticsearch'},
    5601: {'protocol': 'KIBANA', 'description': 'Kibana dashboard'},
    
    # Docker & Kubernetes
    2375: {'protocol': 'DOCKER', 'description': 'Docker API (unencrypted)'},
    2376: {'protocol': 'DOCKER-TLS', 'description': 'Docker API (encrypted)'},
    6443: {'protocol': 'K8S-API', 'description': 'Kubernetes API'},
    10250: {'protocol': 'KUBELET', 'description': 'Kubernetes kubelet'},
    
    # Suspicious/Hacking Ports
    31337: {'protocol': 'BACK-ORIFICE', 'description': 'Known backdoor port', 'suspicious': True},
    12345: {'protocol': 'NETBUS', 'description': 'Trojan port', 'suspicious': True},
    6666: {'protocol': 'IRC-BOT', 'description': 'Common botnet C&C', 'suspicious': True},
    4444: {'protocol': 'METASPLOIT', 'description': 'Common exploit port', 'suspicious': True},
    5555: {'protocol': 'ANDROID-DEBUG', 'description': 'Android Debug Bridge', 'suspicious': True},
    1337: {'protocol': 'LEET', 'description': 'Hacker culture port', 'suspicious': True},
    9001: {'protocol': 'TOR-ORG', 'description': 'Tor network port', 'suspicious': True},
    6881: {'protocol': 'BITTORRENT', 'description': 'BitTorrent', 'suspicious': True},
    6882: {'protocol': 'BITTORRENT', 'description': 'BitTorrent', 'suspicious': True},
    6883: {'protocol': 'BITTORRENT', 'description': 'BitTorrent', 'suspicious': True},
    6884: {'protocol': 'BITTORRENT', 'description': 'BitTorrent', 'suspicious': True},
    6885: {'protocol': 'BITTORRENT', 'description': 'BitTorrent', 'suspicious': True},
}

# Port ranges
REGISTERED_PORT_RANGES = {
    (1024, 49151): 'REGISTERED',
    (49152, 65535): 'DYNAMIC/EPHEMERAL'
}


def get_port_info(port_number):
    if port_number in COMMON_PORTS:
        return COMMON_PORTS[port_number]
    for (start, end), port_type in REGISTERED_PORT_RANGES.items():
        if start <= port_number <= end:
            return {
                'protocol': port_type,
                'description': f'{port_type} port',
                'suspicious': False
            }
    return {
        'protocol': 'UNKNOWN',
        'description': 'Unknown service',
        'suspicious': False
    }


def get_protocol_name(port_number):
    info = get_port_info(port_number)
    return info['protocol']


def is_suspicious_port(port_number):
    if port_number in COMMON_PORTS:
        return COMMON_PORTS[port_number].get('suspicious', False)
    return False


def get_port_description(port_number):
    info = get_port_info(port_number)
    return info['description']


SERVICE_CATEGORIES = {
    'WEB': [80, 443, 8080, 8443, 8008, 8888],
    'EMAIL': [25, 110, 143, 465, 587, 993, 995],
    'FILE_TRANSFER': [20, 21, 22, 69, 115, 989, 990],
    'DATABASE': [1433, 1521, 3306, 5432, 27017, 6379],
    'REMOTE_ACCESS': [22, 23, 3389, 5900, 5901],
    'MESSAGING': [194, 5222, 6667],
    'GAMING': [25565, 27015, 3074, 19132],
    'VPN': [1194, 1723, 500, 4500, 1701],
    'WINDOWS': [135, 137, 138, 139, 445, 1900, 5353, 5355, 3702],
    'SUSPICIOUS': [31337, 12345, 6666, 4444, 5555, 1337, 9001,
                   6881, 6882, 6883, 6884, 6885],
}


def get_service_category(port_number):
    for category, ports in SERVICE_CATEGORIES.items():
        if port_number in ports:
            return category
    return 'OTHER'


__all__ = [
    'COMMON_PORTS',
    'get_port_info',
    'get_protocol_name',
    'is_suspicious_port',
    'get_port_description',
    'get_service_category',
    'SERVICE_CATEGORIES'
]