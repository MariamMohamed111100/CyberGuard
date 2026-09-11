from typing import List, Dict, Any
from datetime import datetime

try:
    from models import Device, PortInfo
except ImportError:
    from .models import Device, PortInfo

class SecurityAdvisor:
    def __init__(self):
        self.advice_db = self._load_advice_database()
    
    def _load_advice_database(self) -> Dict:
        return {
            'unauthorized_device': [
                "Add the device to authorized list or investigate its presence",
                "Check if device has proper security patches",
                "Consider implementing MAC address filtering",
                "Monitor network traffic from this device"
            ],
            'high_risk_port': [
                "Close unnecessary ports on the device",
                "Implement firewall rules to restrict access",
                "Use VPN for remote access instead of open ports",
                "Regularly update services running on these ports"
            ],
            'open_ports': [
                "Close all unused ports",
                "Use port knocking for sensitive services",
                "Implement intrusion detection system",
                "Regular port scanning and auditing"
            ],
            'network_security': [
                "Implement network segmentation",
                "Use strong encryption (WPA3 for WiFi)",
                "Regularly update router firmware",
                "Monitor network for unusual traffic patterns"
            ],
            'general_security': [
                "Enable automatic security updates",
                "Use strong, unique passwords",
                "Implement two-factor authentication",
                "Regular security awareness training"
            ]
        }
    
    def get_advice_for_device(self, device: Device, port_details: List[PortInfo]) -> List[str]:
        advice = []
        
        # Check for unauthorized device
        if not device.is_authorized:
            advice.extend(self.advice_db['unauthorized_device'])
        
        # Check for risky ports
        risky_ports = [p for p in port_details if p.risk_level in ['high', 'medium']]
        if risky_ports:
            advice.extend(self.advice_db['high_risk_port'])
        
        # Check for too many open ports
        if len(device.open_ports) > 5:
            advice.extend(self.advice_db['open_ports'])
        
        # Add general security advice
        advice.extend(self.advice_db['general_security'])
        
        # Preserve order while removing duplicates, then limit to 5
        return list(dict.fromkeys(advice))[:5]
    
    def get_port_specific_advice(self, port: int, service: str) -> List[str]:
        advice = []
        
        port_advice = {
            22: ["Use SSH key authentication instead of passwords", "Change default SSH port", "Use fail2ban to prevent brute force"],
            23: ["Telnet is insecure - use SSH instead", "Disable telnet service immediately"],
            21: ["FTP transmits passwords in clear text - use SFTP or FTPS"],
            3389: ["Restrict RDP access to specific IPs", "Use Network Level Authentication", "Consider using VPN instead"],
            5900: ["Password protect VNC sessions", "Use SSH tunneling for VNC"],
            80: ["Redirect to HTTPS", "Implement security headers", "Use WAF (Web Application Firewall)"],
            443: ["Use strong TLS configurations", "Regular SSL certificate renewal", "Implement HSTS"]
        }
        
        if port in port_advice:
            advice.extend(port_advice[port])
        
        return advice
    
    def generate_security_report(self, devices: List[Device]) -> Dict:
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_devices': len(devices),
            'unauthorized_devices': len([d for d in devices if not d.is_authorized]),
            'open_ports_total': sum(len(d.open_ports) for d in devices),
            'risk_assessment': 'low',
            'security_score': 100,
            'recommendations': []
        }

        # Calculate risk level / score with one consistent set of thresholds
        score = 100
        unauthorized_count = report['unauthorized_devices']
        if unauthorized_count > 3:
            report['risk_assessment'] = 'critical'
        elif unauthorized_count > 1:
            report['risk_assessment'] = 'high'
        elif unauthorized_count > 0:
            report['risk_assessment'] = 'medium'

        score -= unauthorized_count * 20
        if report['open_ports_total'] > 20:
            score -= 10
        report['security_score'] = max(0, min(100, score))

        # Generate recommendations
        if report['unauthorized_devices'] > 0:
            report['recommendations'].append(f"Investigate {report['unauthorized_devices']} unauthorized devices")
        
        if report['open_ports_total'] > 20:
            report['recommendations'].append("Reduce number of open ports on network")
        
        report['recommendations'].append("Conduct regular vulnerability assessments")
        report['recommendations'].append("Implement network monitoring solution")
        
        return report