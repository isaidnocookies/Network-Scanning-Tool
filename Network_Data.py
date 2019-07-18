class Network_Data:

    @staticmethod
    def portInformation(port):
        ports_list = {"80": "HTTP", "8080": "HTTP", "8081": "HTTP", "8888": "HTTP",
            "443": "HTTPS", "7": "Echo", "15": "netstat", "20": "FTP", "21": "FTP",
            "22": "SSH", "23": "Telnet", "25": "SMTP", "49": "TACACS", "67": "BOOTP",
            "68" : "BOOTP", "79": "Finger", "115": "SFTP", "119": "NNTP", "123 " : "NTP",
            "143": "IMAP", "179 " : "BGP", "500": "ISAKMP", "520 " : "RIP", "521": "RIP",
            "546": "DHCPv6", "547": "DHCPv6", "1521": "Oracle", "1433": "MSSQL", "3306": "MySQL",
            "389": "LDAP", "53": "DNS", "111": "RPC", "69": "TFTP", "139": "SMB", "445": "SMB",
            "902": "VMWare", "3389": "RDP", "514": "Syslog", "5900": "VNC", "5800": "VNC", "2049 ": "NFS UDP",
            "4786": "Cisco", "110": "POP3", "623": "IPMI", "161": "SNMP", "162": "SNMP",
            "16992": "Intel AMT", "16993": "Intel AMT", "16994": "Intel AMT", "16995": "Intel AMT", "664": "Intel AMT"}
        if str(port) in ports_list:
            return ports_list[str(port)]
        else:
            return "Unknown"