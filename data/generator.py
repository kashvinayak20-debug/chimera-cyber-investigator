"""
CHIMERA Dataset Generator
Generates realistic enterprise logs with benign background noise (5,000+ events)
and an injected, stealthy, out-of-order 15-step multi-day cyberattack (APT 'Chimera' Heist).
"""

import json
import random
import csv
from datetime import datetime, timedelta

def generate_dataset(benign_count=5000, output_json="data/sample_attack_logs.json", output_csv="data/sample_attack_logs.csv"):
    random.seed(42)
    start_time = datetime(2026, 11, 10, 8, 0, 0)
    
    users = [
        "alice.chen", "bob.smith", "charlie.davis", "david.kim", "emily.watson",
        "frank.miller", "grace.hopper", "helen.troy", "ian.wright", "julia.roberts"
    ]
    
    workstations = [f"WS-FIN-{i:02d}" for i in range(1, 6)] + \
                   [f"WS-ENG-{i:02d}" for i in range(1, 10)] + \
                   [f"WS-HR-{i:02d}" for i in range(1, 4)]
                   
    servers = {
        "DC-CORP-01": {"ip": "10.0.0.5", "type": "DOMAIN_CONTROLLER", "critical": True},
        "FS-CORE-01": {"ip": "10.0.0.12", "type": "FILE_SERVER", "critical": True},
        "DB-PROD-01": {"ip": "10.0.0.25", "type": "DATABASE", "critical": True},
        "MAIL-EXCH-01": {"ip": "10.0.0.8", "type": "MAIL_SERVER", "critical": False},
        "PROXY-GW-01": {"ip": "10.0.0.2", "type": "GATEWAY", "critical": False}
    }
    
    benign_processes = ["chrome.exe", "slack.exe", "excel.exe", "outlook.exe", "teams.exe", "code.exe", "svchost.exe", "explorer.exe"]
    benign_ips = ["142.250.190.46", "13.107.42.14", "151.101.1.140", "172.217.16.206", "52.96.166.130"]
    
    logs = []
    
    # 1. Generate Benign Enterprise Logs (Simulating 3 days of 9-to-5 activity)
    for i in range(benign_count):
        log_id = f"LOG-BNG-{i+1:05d}"
        day_offset = random.choice([0, 1, 2])
        # 95% benign traffic is during business hours (08:30 to 18:00)
        if random.random() < 0.95:
            hour = random.randint(8, 17)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
        else:
            # 5% late workers or automated tasks
            hour = random.choice([7, 18, 19, 20, 21])
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
        event_time = start_time + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)
        user = random.choice(users)
        host = random.choice(workstations)
        
        event_category = random.choices(
            ["AUTH", "PROCESS", "NETWORK", "DNS"],
            weights=[35, 30, 25, 10]
        )[0]
        
        if event_category == "AUTH":
            action = "USER_LOGON"
            event_id = 4624
            target = host
            source = user
            details = f"Successful interactive logon for {user} on {host}"
        elif event_category == "PROCESS":
            action = "PROCESS_CREATE"
            event_id = 4688
            target = random.choice(benign_processes)
            source = host
            details = f"{host} spawned process {target} initiated by {user}"
        elif event_category == "NETWORK":
            action = "NETWORK_CONNECTION"
            event_id = 3
            target = random.choice(benign_ips)
            source = host
            details = f"Outbound HTTPS TCP connection from {host} to {target}:443"
        else:
            action = "DNS_QUERY"
            event_id = 22
            target = "internal-portal.corp.local"
            source = host
            details = f"DNS query from {host} for {target}"
            
        logs.append({
            "log_id": log_id,
            "timestamp": event_time.isoformat() + "Z",
            "source_entity": source,
            "target_entity": target,
            "action": action,
            "event_id": event_id,
            "user": user,
            "host": host,
            "details": details,
            "is_attack": False,
            "threat_stage": "BENIGN"
        })
        
    # 2. Inject Ground-Truth Attack Chain (The 15-Step Stealth APT Campaign)
    # Day 1: Initial Access & Persistence
    attack_events = [
        {
            "log_id": "LOG-ATTK-001",
            "timestamp": (start_time + timedelta(days=0, hours=9, minutes=14, seconds=22)).isoformat() + "Z",
            "source_entity": "185.220.101.5",
            "target_entity": "WS-FIN-04",
            "action": "SPEARPHISH_DELIVERY",
            "event_id": 4688,
            "user": "alice.chen",
            "host": "WS-FIN-04",
            "details": "Malicious payload 'invoice_Q3_details.pdf.exe' delivered to WS-FIN-04 via phishing link from external IP 185.220.101.5",
            "is_attack": True,
            "threat_stage": "INITIAL_ACCESS",
            "mitre_technique": "T1566.002"
        },
        {
            "log_id": "LOG-ATTK-002",
            "timestamp": (start_time + timedelta(days=0, hours=9, minutes=18, seconds=5)).isoformat() + "Z",
            "source_entity": "WS-FIN-04",
            "target_entity": "powershell.exe",
            "action": "PROCESS_SPAWN",
            "event_id": 4688,
            "user": "alice.chen",
            "host": "WS-FIN-04",
            "details": "invoice_Q3_details.pdf.exe spawned hidden powershell.exe with -enc encoded staging download command",
            "is_attack": True,
            "threat_stage": "EXECUTION",
            "mitre_technique": "T1059.001"
        },
        {
            "log_id": "LOG-ATTK-003",
            "timestamp": (start_time + timedelta(days=0, hours=9, minutes=21, seconds=40)).isoformat() + "Z",
            "source_entity": "powershell.exe",
            "target_entity": "185.220.101.5",
            "action": "C2_BEACON",
            "event_id": 3,
            "user": "alice.chen",
            "host": "WS-FIN-04",
            "details": "Reverse TCP tunnel established from WS-FIN-04:49210 to external Command & Control IP 185.220.101.5:8443",
            "is_attack": True,
            "threat_stage": "COMMAND_AND_CONTROL",
            "mitre_technique": "T1071.001"
        },
        {
            "log_id": "LOG-ATTK-004",
            "timestamp": (start_time + timedelta(days=0, hours=14, minutes=2, seconds=15)).isoformat() + "Z",
            "source_entity": "powershell.exe",
            "target_entity": "schtasks.exe",
            "action": "PERSISTENCE_CREATE",
            "event_id": 4698,
            "user": "alice.chen",
            "host": "WS-FIN-04",
            "details": "Scheduled task 'WinAppUpdateHealth' registered to execute payload on user logon and daily at 02:00 AM",
            "is_attack": True,
            "threat_stage": "PERSISTENCE",
            "mitre_technique": "T1053.005"
        },
        # Day 2: Off-Hours Credential Theft & Lateral Movement
        {
            "log_id": "LOG-ATTK-005",
            "timestamp": (start_time + timedelta(days=1, hours=2, minutes=15, seconds=30)).isoformat() + "Z",
            "source_entity": "WS-FIN-04",
            "target_entity": "lsass.exe",
            "action": "CREDENTIAL_DUMP",
            "event_id": 10,
            "user": "alice.chen",
            "host": "WS-FIN-04",
            "details": "Suspicious process memory read access on lsass.exe (MiniDumpWriteDump signature) to harvest cached service credentials",
            "is_attack": True,
            "threat_stage": "CREDENTIAL_ACCESS",
            "mitre_technique": "T1003.001"
        },
        {
            "log_id": "LOG-ATTK-006",
            "timestamp": (start_time + timedelta(days=1, hours=2, minutes=38, seconds=10)).isoformat() + "Z",
            "source_entity": "WS-FIN-04",
            "target_entity": "svc-backup",
            "action": "PRIVILEGE_ESCALATE",
            "event_id": 4672,
            "user": "svc-backup",
            "host": "WS-FIN-04",
            "details": "Special privileges assigned to logon token for privileged service account svc-backup on WS-FIN-04",
            "is_attack": True,
            "threat_stage": "PRIVILEGE_ESCALATION",
            "mitre_technique": "T1078.002"
        },
        {
            "log_id": "LOG-ATTK-007",
            "timestamp": (start_time + timedelta(days=1, hours=2, minutes=55, seconds=45)).isoformat() + "Z",
            "source_entity": "WS-FIN-04",
            "target_entity": "10.0.0.0/24",
            "action": "INTERNAL_RECON",
            "event_id": 3,
            "user": "svc-backup",
            "host": "WS-FIN-04",
            "details": "Automated internal port scan across subnet targeting ports 445 (SMB), 389 (LDAP), and 3389 (RDP)",
            "is_attack": True,
            "threat_stage": "DISCOVERY",
            "mitre_technique": "T1046"
        },
        {
            "log_id": "LOG-ATTK-008",
            "timestamp": (start_time + timedelta(days=1, hours=3, minutes=12, seconds=20)).isoformat() + "Z",
            "source_entity": "WS-FIN-04",
            "target_entity": "WS-ENG-03",
            "action": "LATERAL_LOGON",
            "event_id": 4624,
            "user": "svc-backup",
            "host": "WS-ENG-03",
            "details": "Network logon (Type 3) from WS-FIN-04 to WS-ENG-03 using svc-backup credentials via SMB",
            "is_attack": True,
            "threat_stage": "LATERAL_MOVEMENT",
            "mitre_technique": "T1021.002"
        },
        {
            "log_id": "LOG-ATTK-009",
            "timestamp": (start_time + timedelta(days=1, hours=3, minutes=30, seconds=12)).isoformat() + "Z",
            "source_entity": "WS-ENG-03",
            "target_entity": "wmic.exe",
            "action": "REMOTE_EXECUTION",
            "event_id": 4688,
            "user": "svc-backup",
            "host": "WS-ENG-03",
            "details": "Remote WMI invocation executing staging command on secondary pivot workstation WS-ENG-03",
            "is_attack": True,
            "threat_stage": "EXECUTION",
            "mitre_technique": "T1047"
        },
        # Day 3: High-Value Target Infiltration & Exfiltration
        {
            "log_id": "LOG-ATTK-010",
            "timestamp": (start_time + timedelta(days=2, hours=1, minutes=10, seconds=5)).isoformat() + "Z",
            "source_entity": "WS-ENG-03",
            "target_entity": "DC-CORP-01",
            "action": "KERBEROAST_REQUEST",
            "event_id": 4769,
            "user": "svc-backup",
            "host": "DC-CORP-01",
            "details": "Kerberos service ticket (TGS) requested with RC4 encryption targeting Domain Controller DC-CORP-01",
            "is_attack": True,
            "threat_stage": "CREDENTIAL_ACCESS",
            "mitre_technique": "T1558.003"
        },
        {
            "log_id": "LOG-ATTK-011",
            "timestamp": (start_time + timedelta(days=2, hours=1, minutes=45, seconds=35)).isoformat() + "Z",
            "source_entity": "WS-ENG-03",
            "target_entity": "DC-CORP-01",
            "action": "DOMAIN_ADMIN_TAKEOVER",
            "event_id": 4624,
            "user": "DOMAIN_ADMIN",
            "host": "DC-CORP-01",
            "details": "Interactive logon as DOMAIN_ADMIN to DC-CORP-01 using forged Golden Ticket / cracked Kerberos token",
            "is_attack": True,
            "threat_stage": "LATERAL_MOVEMENT",
            "mitre_technique": "T1078.002"
        },
        {
            "log_id": "LOG-ATTK-012",
            "timestamp": (start_time + timedelta(days=2, hours=2, minutes=15, seconds=40)).isoformat() + "Z",
            "source_entity": "DC-CORP-01",
            "target_entity": "DB-PROD-01",
            "action": "DATABASE_INFILTRATION",
            "event_id": 18456,
            "user": "DOMAIN_ADMIN",
            "host": "DB-PROD-01",
            "details": "Privileged administrative login from DC-CORP-01 to Production Core Database DB-PROD-01 (10.0.0.25:1433)",
            "is_attack": True,
            "threat_stage": "COLLECTION",
            "mitre_technique": "T1021.006"
        },
        {
            "log_id": "LOG-ATTK-013",
            "timestamp": (start_time + timedelta(days=2, hours=2, minutes=48, seconds=15)).isoformat() + "Z",
            "source_entity": "DB-PROD-01",
            "target_entity": "FS-CORE-01",
            "action": "DATA_STAGING",
            "event_id": 5145,
            "user": "DOMAIN_ADMIN",
            "host": "FS-CORE-01",
            "details": "Customer PII & financial records dumped to compressed encrypted container 'payroll_vault_2026.7z' on FS-CORE-01",
            "is_attack": True,
            "threat_stage": "COLLECTION",
            "mitre_technique": "T1560.001"
        },
        {
            "log_id": "LOG-ATTK-014",
            "timestamp": (start_time + timedelta(days=2, hours=3, minutes=20, seconds=50)).isoformat() + "Z",
            "source_entity": "WS-FIN-04",
            "target_entity": "vssadmin.exe",
            "action": "ANTI_FORENSICS",
            "event_id": 4688,
            "user": "alice.chen",
            "host": "WS-FIN-04",
            "details": "Execution of 'vssadmin delete shadows /all /quiet' to destroy volume snapshots and hinder forensic recovery",
            "is_attack": True,
            "threat_stage": "DEFENSE_EVASION",
            "mitre_technique": "T1490"
        },
        {
            "log_id": "LOG-ATTK-015",
            "timestamp": (start_time + timedelta(days=2, hours=3, minutes=55, seconds=10)).isoformat() + "Z",
            "source_entity": "FS-CORE-01",
            "target_entity": "194.26.29.110",
            "action": "DATA_EXFILTRATION",
            "event_id": 3,
            "user": "svc-backup",
            "host": "FS-CORE-01",
            "details": "High-volume 4.8 GB outbound encrypted transfer over port 443 to foreign drop server 194.26.29.110",
            "is_attack": True,
            "threat_stage": "EXFILTRATION",
            "mitre_technique": "T1041"
        }
    ]
    
    logs.extend(attack_events)
    
    # 3. Simulate Realistic Network Ingestion Delay: SHUFFLE LOGS COMPLETELY OUT OF ORDER!
    # Real enterprise log collectors experience out-of-order delivery
    random.shuffle(logs)
    
    # Save to JSON
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)
        
    # Save to CSV
    keys = ["log_id", "timestamp", "source_entity", "target_entity", "action", "event_id", "user", "host", "details", "is_attack", "threat_stage"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(logs)
        
    print(f"Dataset generated successfully:")
    print(f"- Total Logs: {len(logs)}")
    print(f"- Benign Noise Logs: {benign_count}")
    print(f"- Stealth Attack Chain Events: {len(attack_events)}")
    print(f"- Files saved to: {output_json} & {output_csv}")
    return logs

if __name__ == "__main__":
    generate_dataset()
