import unittest
from unittest.mock import MagicMock
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

# Make sure port_database.py is in the same folder
from advanced_packet_sniffer import (
    PacketParser,
    PacketFilter,
    PacketStorage,
    AlertSystem
)


# ─────────────────────────────────────────────
# TEST CLASS 1: PacketParser
# ─────────────────────────────────────────────
class TestPacketParser(unittest.TestCase):
    """Unit tests for PacketParser.parse_packet()"""

    def test_tcp_http_identified(self):
        """parse_packet() should identify TCP port 80 as HTTP"""
        pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=80)
        result = PacketParser.parse_packet(pkt)
        self.assertEqual(result['protocol'], 'HTTP')
        self.assertEqual(result['src'], '192.168.1.10')
        self.assertEqual(result['dst'], '93.184.216.34')

    def test_tcp_https_identified(self):
        """parse_packet() should identify TCP port 443 as HTTPS"""
        pkt = IP(src="10.0.0.1", dst="1.1.1.1") / TCP(sport=55000, dport=443)
        result = PacketParser.parse_packet(pkt)
        self.assertEqual(result['protocol'], 'HTTPS')

    def test_udp_dns_identified(self):
        """parse_packet() should identify UDP port 53 as DNS"""
        pkt = IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=12345, dport=53)
        result = PacketParser.parse_packet(pkt)
        self.assertEqual(result['protocol'], 'DNS')

    def test_tcp_ssh_identified(self):
        """parse_packet() should identify TCP port 22 as SSH"""
        pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=60000, dport=22)
        result = PacketParser.parse_packet(pkt)
        self.assertEqual(result['protocol'], 'SSH')

    def test_icmp_identified(self):
        """parse_packet() should identify ICMP echo request"""
        pkt = IP(src="192.168.1.1", dst="8.8.8.8") / ICMP(type=8)
        result = PacketParser.parse_packet(pkt)
        self.assertEqual(result['protocol'], 'ICMP')
        self.assertEqual(result['info'], 'Echo Request (Ping)')

    def test_ipv6_packet_parsed(self):
        """parse_packet() should handle IPv6 packets"""
        pkt = IPv6(src="::1", dst="::2") / TCP(sport=12345, dport=80)
        result = PacketParser.parse_packet(pkt)
        self.assertEqual(result['protocol'], 'HTTP')
        self.assertEqual(result['src'], '::1')

    def test_no_ip_layer_returns_unknown(self):
        """parse_packet() should return 'Unknown' when no IP layer present"""
        from scapy.layers.l2 import Ether
        pkt = Ether()
        result = PacketParser.parse_packet(pkt)
        self.assertEqual(result['protocol'], 'Unknown')
        self.assertEqual(result['src'], 'N/A')

    def test_packet_info_has_required_keys(self):
        """parse_packet() output must contain all required dictionary keys"""
        pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=443)
        result = PacketParser.parse_packet(pkt)
        required_keys = [
            'timestamp', 'length', 'protocol', 'src', 'dst',
            'src_port', 'dst_port', 'info', 'flags', 'payload', 'suspicious'
        ]
        for key in required_keys:
            self.assertIn(key, result, msg=f"Missing key: {key}")


# ─────────────────────────────────────────────
# TEST CLASS 2: PacketFilter
# ─────────────────────────────────────────────
class TestPacketFilter(unittest.TestCase):
    """Unit tests for PacketFilter.matches_filter()"""

    def setUp(self):
        self.packets = [
            {'protocol': 'HTTP',  'src': '192.168.1.10', 'dst': '93.184.216.34',
             'src_port': 54321, 'dst_port': 80,  'info': 'GET /', 'suspicious': False},
            {'protocol': 'DNS',   'src': '192.168.1.10', 'dst': '8.8.8.8',
             'src_port': 12345, 'dst_port': 53,  'info': 'Query: google.com', 'suspicious': False},
            {'protocol': 'HTTPS', 'src': '10.0.0.1',     'dst': '1.1.1.1',
             'src_port': 55000, 'dst_port': 443, 'info': 'TLS handshake', 'suspicious': False},
            {'protocol': 'SSH',   'src': '10.0.0.5',     'dst': '10.0.0.1',
             'src_port': 60000, 'dst_port': 22,  'info': 'SSH handshake', 'suspicious': True},
        ]

    def _apply(self, filters):
        return [p for p in self.packets
                if PacketFilter.matches_filter(p, filters)]

    def test_no_filters_returns_all(self):
        """Empty filter dict should return all packets"""
        result = self._apply({})
        self.assertEqual(len(result), 4)

    def test_protocol_filter(self):
        """Protocol filter should return only matching packets"""
        result = self._apply({'protocol': 'DNS'})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['protocol'], 'DNS')

    def test_protocol_all_returns_all(self):
        """Protocol='All' should not filter anything"""
        result = self._apply({'protocol': 'All'})
        self.assertEqual(len(result), 4)

    def test_src_ip_partial_match(self):
        """src_ip filter should support partial substring matching"""
        result = self._apply({'src_ip': '192.168'})
        self.assertEqual(len(result), 2)

    def test_dst_ip_filter(self):
        """dst_ip filter should match destination IP substring"""
        result = self._apply({'dst_ip': '8.8'})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['protocol'], 'DNS')

    def test_port_filter(self):
        """Port filter should match src or dst port"""
        result = self._apply({'port': '443'})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['protocol'], 'HTTPS')

    def test_search_term_filter(self):
        """search_term should match across src, dst, info, protocol fields"""
        result = self._apply({'search_term': 'google'})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['protocol'], 'DNS')

    def test_suspicious_only_filter(self):
        """suspicious_only=True should return only flagged packets"""
        result = self._apply({'suspicious_only': True})
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['suspicious'])

    def test_combined_and_logic(self):
        """Multiple filters must ALL pass (AND logic)"""
        result = self._apply({'protocol': 'DNS', 'dst_ip': '8.8'})
        self.assertEqual(len(result), 1)
        # Wrong protocol but matching IP should not appear
        result2 = self._apply({'protocol': 'HTTP', 'dst_ip': '8.8'})
        self.assertEqual(len(result2), 0)


# ─────────────────────────────────────────────
# TEST CLASS 3: PacketStorage
# ─────────────────────────────────────────────
class TestPacketStorage(unittest.TestCase):
    """Unit tests for PacketStorage"""

    def setUp(self):
        self.storage = PacketStorage()
        self.sample = {
            'protocol': 'HTTP', 'src': '1.1.1.1', 'dst': '2.2.2.2',
            'src_port': 54321, 'dst_port': 80, 'length': 200,
            'suspicious': False, 'info': 'GET /'
        }

    def test_add_and_retrieve(self):
        """add_packet() then get_all_packets() should return the packet"""
        self.storage.add_packet(self.sample)
        result = self.storage.get_all_packets()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['protocol'], 'HTTP')

    def test_get_packet_count(self):
        """get_packet_count() should return correct count"""
        for _ in range(5):
            self.storage.add_packet(self.sample)
        self.assertEqual(self.storage.get_packet_count(), 5)

    def test_clear_resets_storage(self):
        """clear() should empty all packets and reset statistics"""
        self.storage.add_packet(self.sample)
        self.storage.clear()
        self.assertEqual(self.storage.get_packet_count(), 0)
        self.assertEqual(self.storage.total_bytes, 0)
        self.assertEqual(self.storage.suspicious_count, 0)

    def test_protocol_count_updated(self):
        """add_packet() should update protocol_count correctly"""
        self.storage.add_packet(self.sample)
        self.storage.add_packet({**self.sample, 'protocol': 'DNS'})
        self.assertEqual(self.storage.protocol_count['HTTP'], 1)
        self.assertEqual(self.storage.protocol_count['DNS'], 1)

    def test_suspicious_count_updated(self):
        """add_packet() should increment suspicious_count for flagged packets"""
        self.storage.add_packet({**self.sample, 'suspicious': True})
        self.storage.add_packet(self.sample)
        self.assertEqual(self.storage.suspicious_count, 1)

    def test_get_statistics_structure(self):
        """get_statistics() should return dict with all expected keys"""
        self.storage.add_packet({**self.sample, 'length': 200})
        stats = self.storage.get_statistics()
        expected_keys = [
            'total_packets', 'protocol_distribution', 'total_bytes',
            'average_packet_size', 'packets_per_second',
            'top_conversations', 'suspicious_count'
        ]
        for key in expected_keys:
            self.assertIn(key, stats, msg=f"Missing stats key: {key}")

    def test_insertion_order_preserved(self):
        """Packets should be returned in insertion order"""
        for i in range(5):
            self.storage.add_packet({**self.sample, 'info': f'packet_{i}'})
        result = self.storage.get_all_packets()
        for i, pkt in enumerate(result):
            self.assertEqual(pkt['info'], f'packet_{i}')


# ─────────────────────────────────────────────
# TEST CLASS 4: AlertSystem
# ─────────────────────────────────────────────
class TestAlertSystem(unittest.TestCase):
    """Unit tests for AlertSystem"""

    def setUp(self):
        self.alerts_received = []
        def mock_callback(message, packet_info):
            self.alerts_received.append((message, packet_info))
        self.alert_system = AlertSystem(mock_callback)

    def test_suspicious_port_triggers_alert(self):
        """check_packet() should fire alert_callback for suspicious packets"""
        pkt = {
            'protocol': 'TCP', 'suspicious': True,
            'src': '10.0.0.1', 'dst': '10.0.0.2',
            'dst_port': 31337, 'src_port': 54321
        }
        self.alert_system.check_packet(pkt)
        self.assertEqual(len(self.alerts_received), 1)
        self.assertIn('31337', self.alerts_received[0][0])

    def test_normal_packet_no_alert(self):
        """check_packet() should not fire for non-suspicious packets"""
        pkt = {
            'protocol': 'HTTP', 'suspicious': False,
            'src': '192.168.1.1', 'dst': '93.184.216.34',
            'dst_port': 80, 'src_port': 54321
        }
        self.alert_system.check_packet(pkt)
        self.assertEqual(len(self.alerts_received), 0)

    def test_alert_cooldown_prevents_duplicate(self):
        """Same alert should not fire again within cooldown period"""
        pkt = {
            'protocol': 'TCP', 'suspicious': True,
            'src': '10.0.0.1', 'dst': '10.0.0.2',
            'dst_port': 31337, 'src_port': 54321
        }
        self.alert_system.check_packet(pkt)
        self.alert_system.check_packet(pkt)  # Second call within cooldown
        self.assertEqual(len(self.alerts_received), 1)  # Still only 1

    def test_different_ports_generate_separate_alerts(self):
        """Different suspicious ports should each generate their own alert"""
        for port in [31337, 1337, 4444]:
            pkt = {
                'protocol': 'TCP', 'suspicious': True,
                'src': '10.0.0.1', 'dst': '10.0.0.2',
                'dst_port': port, 'src_port': 54321
            }
            self.alert_system.check_packet(pkt)
        self.assertEqual(len(self.alerts_received), 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)