"""
Deep Packet Inspection (DPI) module
For identifying service types and protocols used
"""
from typing import Dict, Any, Optional
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

from app.collectors.protocols import protocol_name

try:
    from scapy.layers.inet6 import ICMPv6Unknown  # type: ignore
except ImportError:  # pragma: no cover
    ICMPv6Unknown = None


class PacketAnalyzer:
    """Network packet analysis class"""

    # Known ports for service identification
    SERVICE_PORTS = {
        20: "FTP_DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5060: "SIP",
        5061: "SIPS",
        8080: "HTTP_PROXY",
        8443: "HTTPS_ALT",
    }

    # Application identification patterns
    APPLICATION_PATTERNS = {
        "HTTP": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
        "HTTPS": ["TLS", "SSL"],
        "FTP": ["220", "331", "230"],
        "SMTP": ["220", "250", "354"],
        "POP3": ["+OK", "-ERR"],
        "IMAP": ["* OK", "* BYE"],
        "DNS": ["\x00\x01", "\x00\x02"],
        "SSH": ["SSH-"],
        "VoIP": ["SIP/", "INVITE", "REGISTER"],
    }

    @staticmethod
    def analyze_packet(packet_data: bytes) -> Dict[str, Any]:
        """
        Analyze a packet and extract information
        
        Args:
            packet_data: Packet data as bytes
            
        Returns:
            Dictionary containing analyzed information
        """
        result = {
            "protocol": "UNKNOWN",
            "protocol_number": None,
            "ip_version": None,
            "source_ip": None,
            "destination_ip": None,
            "service_type": None,
            "application_name": None,
            "classification": {},
            "is_suspicious": False,
            "threat_indicators": []
        }

        try:
            # Prefer IPv6, then IPv4
            packet = None
            if len(packet_data) >= 1 and (packet_data[0] >> 4) == 6:
                packet = IPv6(packet_data)
                result["ip_version"] = 6
                result["source_ip"] = packet.src
                result["destination_ip"] = packet.dst
                result["protocol_number"] = int(packet.nh)
                result["protocol"] = protocol_name(packet.nh)
            else:
                packet = IP(packet_data)
                result["ip_version"] = 4
                result["source_ip"] = packet.src
                result["destination_ip"] = packet.dst
                result["protocol_number"] = int(packet.proto)
                result["protocol"] = protocol_name(packet.proto)

            if packet.haslayer(TCP):
                result["protocol"] = "TCP"
                result["protocol_number"] = 6
                tcp_layer = packet[TCP]
                result["classification"]["tcp_flags"] = {
                    "syn": bool(tcp_layer.flags & 0x02),
                    "ack": bool(tcp_layer.flags & 0x10),
                    "fin": bool(tcp_layer.flags & 0x01),
                    "rst": bool(tcp_layer.flags & 0x04),
                }
                
                # Identify service based on port
                dst_port = tcp_layer.dport
                src_port = tcp_layer.sport
                
                if dst_port in PacketAnalyzer.SERVICE_PORTS:
                    result["service_type"] = PacketAnalyzer.SERVICE_PORTS[dst_port]
                elif src_port in PacketAnalyzer.SERVICE_PORTS:
                    result["service_type"] = PacketAnalyzer.SERVICE_PORTS[src_port]
                
                # Analyze HTTP content
                if packet.haslayer(HTTPRequest):
                    http_req = packet[HTTPRequest]
                    result["service_type"] = "HTTP"
                    result["application_name"] = "HTTP_Client"
                    result["classification"]["http_method"] = http_req.Method.decode() if http_req.Method else None
                    result["classification"]["http_host"] = http_req.Host.decode() if http_req.Host else None
                    result["classification"]["http_path"] = http_req.Path.decode() if http_req.Path else None
                    
                    # Extract User-Agent
                    if http_req.haslayer(Raw):
                        raw_data = http_req[Raw].load.decode('utf-8', errors='ignore')
                        if "User-Agent:" in raw_data:
                            ua_line = [line for line in raw_data.split('\n') if 'User-Agent:' in line]
                            if ua_line:
                                result["classification"]["user_agent"] = ua_line[0].split('User-Agent:')[1].strip()
                
                elif packet.haslayer(HTTPResponse):
                    result["service_type"] = "HTTP"
                    result["application_name"] = "HTTP_Server"
                    http_resp = packet[HTTPResponse]
                    result["classification"]["http_status"] = http_resp.Status_Code.decode() if http_resp.Status_Code else None
                
                # Analyze Raw content for application identification
                elif packet.haslayer(Raw):
                    raw_data = packet[Raw].load
                    result.update(PacketAnalyzer._analyze_raw_content(raw_data, dst_port, src_port))
                
            elif packet.haslayer(UDP):
                result["protocol"] = "UDP"
                result["protocol_number"] = 17
                udp_layer = packet[UDP]
                dst_port = udp_layer.dport
                src_port = udp_layer.sport
                
                if dst_port in PacketAnalyzer.SERVICE_PORTS:
                    result["service_type"] = PacketAnalyzer.SERVICE_PORTS[dst_port]
                elif src_port in PacketAnalyzer.SERVICE_PORTS:
                    result["service_type"] = PacketAnalyzer.SERVICE_PORTS[src_port]
                
                # Analyze DNS
                if dst_port == 53 or src_port == 53:
                    result["service_type"] = "DNS"
                    result["application_name"] = "DNS"
                
                # Analyze SIP (VoIP)
                if dst_port in [5060, 5061] or src_port in [5060, 5061]:
                    result["service_type"] = "VoIP"
                    result["application_name"] = "SIP"
                    if packet.haslayer(Raw):
                        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        if any(pattern in raw_data for pattern in ["INVITE", "REGISTER", "BYE", "ACK"]):
                            result["classification"]["sip_method"] = raw_data.split()[0] if raw_data.split() else None
                
            elif packet.haslayer(ICMP):
                result["protocol"] = "ICMP"
                result["protocol_number"] = 1
                result["service_type"] = "ICMP"
                icmp_layer = packet[ICMP]
                result["classification"]["icmp_type"] = icmp_layer.type
                result["classification"]["icmp_code"] = icmp_layer.code
            elif (ICMPv6Unknown and packet.haslayer(ICMPv6Unknown)) or (
                result.get("ip_version") == 6 and result.get("protocol_number") == 58
            ):
                result["protocol"] = "ICMPv6"
                result["protocol_number"] = 58
                result["service_type"] = "ICMPv6"

            # Check security threats
            result.update(PacketAnalyzer._detect_threats(packet, result))

        except Exception as e:
            result["classification"]["error"] = str(e)
            if result.get("protocol") == "UNKNOWN":
                result["protocol"] = "UNKNOWN"

        return result

    @staticmethod
    def _analyze_raw_content(raw_data: bytes, dst_port: int, src_port: int) -> Dict[str, Any]:
        """Analyze Raw content for application identification"""
        result = {
            "service_type": None,
            "application_name": None,
            "classification": {}
        }
        
        try:
            content = raw_data.decode('utf-8', errors='ignore')
            
            # Check application patterns
            for app_name, patterns in PacketAnalyzer.APPLICATION_PATTERNS.items():
                if any(pattern in content for pattern in patterns):
                    result["application_name"] = app_name
                    if app_name in ["HTTP", "HTTPS"]:
                        result["service_type"] = app_name
                    break
            
            # Identify specific protocols
            if content.startswith("SSH-"):
                result["service_type"] = "SSH"
                result["application_name"] = "SSH"
            elif "FTP" in content[:10]:
                result["service_type"] = "FTP"
                result["application_name"] = "FTP"
            elif "SMTP" in content[:10] or "220" in content[:10]:
                result["service_type"] = "SMTP"
                result["application_name"] = "SMTP"
                
        except:
            pass
        
        return result

    @staticmethod
    def _detect_threats(packet: Any, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Detect potential security threats"""
        threats = []
        is_suspicious = False
        
        try:
            # Check suspicious ports
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                suspicious_ports = [4444, 31337, 12345, 54321]  # Known backdoor ports
                if tcp.dport in suspicious_ports or tcp.sport in suspicious_ports:
                    threats.append("suspicious_port")
                    is_suspicious = True
                
                # Check suspicious flags
                if tcp.flags & 0x04:  # RST flag
                    if not (tcp.flags & 0x10):  # Without ACK
                        threats.append("unusual_rst")
                
                # Check port scanning
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN without ACK
                    if analysis_result.get("service_type") is None:
                        threats.append("possible_port_scan")
                        is_suspicious = True
            
            # Check suspicious content
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    content = raw_data.decode('utf-8', errors='ignore').lower()
                    suspicious_keywords = [
                        "password", "passwd", "admin", "root",
                        "exploit", "shell", "cmd", "exec",
                        "union select", "drop table", "1=1"
                    ]
                    if any(keyword in content for keyword in suspicious_keywords):
                        threats.append("suspicious_content")
                        is_suspicious = True
                except:
                    pass
            
        except Exception as e:
            pass
        
        return {
            "is_suspicious": is_suspicious or analysis_result.get("is_suspicious", False),
            "threat_indicators": threats + analysis_result.get("threat_indicators", [])
        }

    @staticmethod
    def classify_service(protocol: str, src_port: int, dst_port: int, 
                        packet_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Classify service based on protocol and port
        
        Args:
            protocol: Protocol (TCP, UDP, ICMP)
            src_port: Source port
            dst_port: Destination port
            packet_data: Packet data (optional)
            
        Returns:
            Classified information
        """
        result = {
            "service_type": None,
            "application_name": None
        }
        
        # Check destination port
        if dst_port in PacketAnalyzer.SERVICE_PORTS:
            result["service_type"] = PacketAnalyzer.SERVICE_PORTS[dst_port]
        elif src_port in PacketAnalyzer.SERVICE_PORTS:
            result["service_type"] = PacketAnalyzer.SERVICE_PORTS[src_port]
        
        # If packet data is available, perform deeper analysis
        if packet_data:
            deep_analysis = PacketAnalyzer.analyze_packet(packet_data)
            if deep_analysis.get("service_type"):
                result["service_type"] = deep_analysis["service_type"]
            if deep_analysis.get("application_name"):
                result["application_name"] = deep_analysis["application_name"]
        
        return result
