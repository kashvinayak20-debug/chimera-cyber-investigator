"""
Synthetic sample log generator.

Produces three heterogeneous log files plus a ground-truth file describing the
injected attack chain (the scenario from Section 1 of the paper):

  10:20 Windows logon (jsmith @ PC-001)
  10:24 PowerShell execution (encoded command)
  10:28 Credential dump (Sysmon 10, lsass.exe handle)
  10:31 VPN login by the same resolved entity
  10:35 Database access over the VPN tunnel IP
  10:39 ZIP archive created
  10:42 External upload (large outbound transfer)

Everything else is seeded benign noise from other hosts / users, plus a routine
PowerShell script on a server (a lower-confidence decoy chain).
The pipeline never reads the ground truth; it is only used by evaluate.py.

    python -m forensic.sample_data [--seed 7] [--out data/samples]
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

BASE = datetime(2026, 7, 8, 8, 0, 0)          # UTC
HOSTS = {
    "PC-001": {"ip": "192.168.1.25", "user": "jsmith"},
    "PC-002": {"ip": "192.168.1.30", "user": "amartin"},
    "PC-003": {"ip": "192.168.1.31", "user": "rkumar"},
    "SRV-01": {"ip": "10.0.5.10", "user": "svc_backup"},
}
DB_SERVER = "10.0.5.20"
ATTACKER_IP = "203.0.113.50"
BENIGN_EXTERNAL = ["198.51.100.7", "198.51.100.22", "198.51.100.90"]
BENIGN_PROCS = ["chrome.exe", "outlook.exe", "explorer.exe", "teams.exe", "notepad.exe", "excel.exe"]
BENIGN_FILES = ["report.docx", "budget.xlsx", "notes.txt", "slides.pptx", "invoice.pdf"]
WIN_COLUMNS = ["TimeCreated", "Channel", "EventID", "Computer", "User", "LogonType", "Image", "CommandLine",
               "TargetFilename", "TargetImage", "GrantedAccess", "SourceIp", "DestinationIp", "DestinationPort", "Message"]


def win_ts(t: datetime) -> str:
    return t.strftime("%m/%d/%Y %I:%M:%S %p")        # Windows Event Viewer style


def epoch(t: datetime) -> str:
    return str(int((t - datetime(1970, 1, 1)).total_seconds()))


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _win(t, channel, eid, host, user, **kw) -> dict:
    row = {c: "" for c in WIN_COLUMNS}
    row.update({"TimeCreated": win_ts(t), "Channel": channel, "EventID": eid, "Computer": host, "User": f"CORP\\{user}"})
    row.update(kw)
    return row


def generate(seed: int = 7, out_dir: str | Path = "data/samples") -> dict:
    rng = random.Random(seed)
    win, fw, vpn, truth = [], [], [], []

    # ------------------------------------------------------------- benign noise
    for host, info in HOSTS.items():
        user, ip = info["user"], info["ip"]
        t = BASE + timedelta(minutes=rng.randint(0, 40))
        win.append(_win(t, "Security", 4624, host, user, LogonType=2, Message="An account was successfully logged on."))
        for _ in range(rng.randint(6, 10)):                       # process starts
            t += timedelta(minutes=rng.randint(4, 25))
            proc = rng.choice(BENIGN_PROCS)
            win.append(_win(t, "Sysmon", 1, host, user, Image=f"C:\\Program Files\\{proc}", CommandLine=f'"{proc}"'))
        for _ in range(rng.randint(3, 5)):                        # file creates
            t += timedelta(minutes=rng.randint(3, 20))
            win.append(_win(t, "Sysmon", 11, host, user, Image="C:\\Windows\\explorer.exe",
                            TargetFilename=f"C:\\Users\\{user}\\Documents\\{rng.choice(BENIGN_FILES)}"))
        for _ in range(rng.randint(4, 7)):                        # network connects (host <-> IP mapping)
            t2 = BASE + timedelta(minutes=rng.randint(0, 290))
            dst = rng.choice(BENIGN_EXTERNAL)
            win.append(_win(t2, "Sysmon", 3, host, user, Image="C:\\Program Files\\chrome.exe",
                            SourceIp=ip, DestinationIp=dst, DestinationPort=443))
            fw.append((t2 + timedelta(seconds=1), f"action=ALLOW src={ip} spt={rng.randint(49152, 65535)} dst={dst} dpt=443 "
                                                  f"proto=TCP bytes_out={rng.randint(2000, 900000)} bytes_in={rng.randint(5000, 3000000)}"))
    # a failed logon, a blocked connection, a legitimate app-server DB query
    win.append(_win(BASE + timedelta(minutes=95), "Security", 4625, "PC-003", "rkumar", LogonType=2, Message="Bad password"))
    win.append(_win(BASE + timedelta(minutes=96), "Security", 4624, "PC-003", "rkumar", LogonType=2, Message="Logged on"))
    fw.append((BASE + timedelta(minutes=130), f"action=DENY src=192.168.1.31 spt=52233 dst=203.0.113.99 dpt=8443 proto=TCP bytes_out=0 bytes_in=0"))
    for m in (30, 75, 160, 240):
        fw.append((BASE + timedelta(minutes=m), f"action=ALLOW src=10.0.5.10 spt={rng.randint(49152, 65535)} dst={DB_SERVER} dpt=1433 "
                                               f"proto=TCP bytes_out={rng.randint(3000, 40000)} bytes_in={rng.randint(50000, 900000)}"))
    # routine PowerShell maintenance on SRV-01 (decoy: suspicious but incomplete chain)
    t = BASE + timedelta(minutes=150)
    win.append(_win(t, "Sysmon", 1, "SRV-01", "svc_backup", Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    CommandLine="powershell.exe -File C:\\Scripts\\nightly_backup.ps1"))
    win.append(_win(t + timedelta(minutes=2), "Sysmon", 11, "SRV-01", "svc_backup", Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    TargetFilename="C:\\Backups\\db_backup_20260708.zip"))
    # other users' VPN sessions
    for user, cip, aip, dev, start in (("amartin", "192.168.1.30", "10.8.0.21", "Laptop-AM", 25),
                                       ("rkumar", "192.168.1.31", "10.8.0.22", "Laptop-RK", 200)):
        s = f"S-{rng.randint(4000, 4999)}"
        vpn.append((BASE + timedelta(minutes=start), f'action=connect user={user} session={s} device="{dev}" client_ip={cip} assigned_ip={aip}'))
        vpn.append((BASE + timedelta(minutes=start + rng.randint(60, 120)), f"action=disconnect user={user} session={s} bytes={rng.randint(10**6, 10**8)}"))
    vpn.append((BASE + timedelta(minutes=190), 'action=auth_failed user=rkumar session=- device="Laptop-RK" client_ip=192.168.1.31 reason=bad_otp'))

    # ------------------------------------------------------------- attack chain (Section 1 scenario)
    A = BASE + timedelta(hours=2, minutes=20)           # 10:20 UTC
    jit = lambda: timedelta(seconds=rng.randint(0, 40))
    steps = [
        ("windows_sysmon", "LOGIN", A + jit(),
         lambda t: win.append(_win(t, "Security", 4624, "PC-001", "jsmith", LogonType=2, Message="An account was successfully logged on."))),
        ("windows_sysmon", "POWERSHELL_EXEC", A + timedelta(minutes=4) + jit(),
         lambda t: win.append(_win(t, "Sysmon", 1, "PC-001", "jsmith", Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                   CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."))),
        ("windows_sysmon", "CREDENTIAL_DUMP", A + timedelta(minutes=8) + jit(),
         lambda t: win.append(_win(t, "Sysmon", 10, "PC-001", "jsmith", Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                   TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1010"))),
        ("vpn_auth", "VPN_LOGIN", A + timedelta(minutes=11) + jit(),
         lambda t: vpn.append((t, 'action=connect user=jsmith session=S-4471 device="User Device" client_ip=192.168.1.25 assigned_ip=10.8.0.14'))),
        ("firewall", "DB_ACCESS", A + timedelta(minutes=15) + jit(),
         lambda t: fw.append((t, f"action=ALLOW src=10.8.0.14 spt=51544 dst={DB_SERVER} dpt=1433 proto=TCP bytes_out=48211 bytes_in=412665344"))),
        ("windows_sysmon", "ARCHIVE_CREATED", A + timedelta(minutes=19) + jit(),
         lambda t: win.append(_win(t, "Sysmon", 11, "PC-001", "jsmith", Image="C:\\Program Files\\7-Zip\\7z.exe",
                                   TargetFilename="C:\\Users\\jsmith\\AppData\\Local\\Temp\\export_2026.zip"))),
        ("firewall", "EXTERNAL_UPLOAD", A + timedelta(minutes=22) + jit(),
         lambda t: fw.append((t, f"action=ALLOW src=192.168.1.25 spt=51610 dst={ATTACKER_IP} dpt=443 proto=TCP bytes_out=524288000 bytes_in=9120"))),
    ]
    for source, event_type, t, emit in steps:
        emit(t)
        truth.append({"source": source, "event_type": event_type, "timestamp": t.strftime("%Y-%m-%d %H:%M:%S")})
    # a Sysmon 3 record so PC-001 <-> 192.168.1.25 is linkable even before the attack window
    win.append(_win(A - timedelta(minutes=50), "Sysmon", 3, "PC-001", "jsmith", Image="C:\\Program Files\\outlook.exe",
                    SourceIp="192.168.1.25", DestinationIp="198.51.100.7", DestinationPort=443))

    # ------------------------------------------------------------- write files
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    win.sort(key=lambda r: datetime.strptime(r["TimeCreated"], "%m/%d/%Y %I:%M:%S %p"))
    with open(out / "windows_sysmon.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=WIN_COLUMNS)
        w.writeheader()
        w.writerows(win)
    fw.sort(key=lambda r: r[0])
    (out / "firewall.log").write_text("\n".join(f"{epoch(t)} {line}" for t, line in fw) + "\n", encoding="utf-8")
    vpn.sort(key=lambda r: r[0])
    (out / "vpn_auth.log").write_text("\n".join(f"{iso(t)} vpn-gw01 {line}" for t, line in vpn) + "\n", encoding="utf-8")
    gt = {"seed": seed, "attack_chain": truth, "entity": {"host": "PC-001", "ip": "192.168.1.25", "vpn_session": "S-4471"},
          "missing_stage": "PRIVILEGE_ESCALATION"}
    (out / "ground_truth.json").write_text(json.dumps(gt, indent=2), encoding="utf-8")
    return {"windows": len(win), "firewall": len(fw), "vpn": len(vpn), "attack_events": len(truth), "out": str(out)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "data" / "samples"))
    args = ap.parse_args()
    print(generate(args.seed, args.out))
