#!/usr/bin/env python3
import time
import os
import json
import requests
import subprocess
import folium
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from folium.plugins import MarkerCluster

# --- CONFIGURATION ---
console = Console()
VT_KEY = "7435e5fbfdb68e09cd7ac71f0940c7478184db7d22e67d99616f0ca74bf7f0ee"
ABUSE_KEY = "36708525ef9d051c8a92da499b7c650acde1a474008f027af3a68268020fd6b2c247922f3fda8a2e"
WHITELIST = ["127.0.0.1", "8.8.8.8", "1.1.1.1"]
BAN_LOG = "active_bans.json"

# --- FIREWALL MODULE ---
def apply_firewall_block(ip):
    if ip in WHITELIST: return "[cyan]WHITELISTED[/]"
    try:
        # Check if already blocked in UFW
        check = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)
        if ip in check.stdout: return "[yellow]ALREADY BANNED[/]"
        
        # Apply the ban
        subprocess.run(['sudo', 'ufw', 'deny', 'from', ip], check=True, capture_output=True)
        
        # Log for Auto-Unblock (24h TTL)
        expiry = (datetime.now() + timedelta(hours=24)).isoformat()
        bans = {}
        if os.path.exists(BAN_LOG):
            with open(BAN_LOG, 'r') as f: bans = json.load(f)
        bans[ip] = expiry
        with open(BAN_LOG, 'w') as f: json.dump(bans, f)
        
        return "[bold red]BANNED[/]"
    except: return "[dim red]FW ERROR[/]"

# --- INTELLIGENCE MODULES ---
def get_intel(ip):
    # AbuseIPDB Check
    abuse_score = 0
    try:
        r = requests.get('https://api.abuseipdb.com/api/v2/check', 
                         headers={'Accept': 'application/json', 'Key': ABUSE_KEY},
                         params={'ipAddress': ip, 'maxAgeInDays': '90'})
        abuse_score = r.json()['data']['abuseConfidenceScore']
    except: pass

    # VirusTotal Check
    vt_hits = 0
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
                         headers={"x-apikey": VT_KEY})
        if r.status_code == 200:
            vt_hits = r.json()['data']['attributes']['last_analysis_stats']['malicious']
    except: pass

    return abuse_score, vt_hits

# --- MAP GENERATION MODULE ---
def generate_map(results):
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    marker_cluster = MarkerCluster().add_to(m)
    
    for entry in results:
        ip = entry['ip']
        color = "red" if entry['is_bad'] else "green"
        icon = "shield" if entry['is_bad'] else "check"
        
        # Use HTML for the map popup (Bypasses terminal formatting)
        status_text = "<span style='color:red; font-weight:bold;'>MALICIOUS</span>" if entry['is_bad'] else "CLEAN"
        popup_html = f"<b>IP:</b> {ip}<br><b>Status:</b> {status_text}<br><b>Score:</b> {entry['abuse']}%"

        try:
            geo = requests.get(f"http://ip-api.com/json/{ip}").json()
            if geo['status'] == 'success':
                folium.Marker(
                    location=[geo['lat'], geo['lon']],
                    popup=folium.Popup(popup_html, max_width=200),
                    tooltip=f"{ip} ({status_text})",
                    icon=folium.Icon(color=color, icon=icon, prefix='fa')
                ).add_to(marker_cluster)
        except: continue
    
    m.save("threat_map.html")

# --- MAIN ENGINE ---
def main():
    if not os.path.exists("iocs.txt"):
        console.print("[bold red][!] Error: iocs.txt missing![/]")
        return
    
    with open("iocs.txt", "r") as f:
        targets = [line.strip() for line in f if line.strip() and "." in line]

    # UI Header
    os.system('clear')
    console.print(Panel.fit("[bold red]STP (Shield Threat Protection) v6.0[/]\n[white]Unified Detection, Blocking, & Mapping Engine[/]", border_style="red"))

    table = Table(title="[bold cyan]Real-Time Threat Intelligence Monitor[/]", show_lines=True)
    table.add_column("Target IP", style="bold white")
    table.add_column("Abuse %", justify="center")
    table.add_column("VT Hits", justify="center")
    table.add_column("IPS Action", justify="center")
    table.add_column("Verdict", justify="right")

    final_results = []

    with Live(table, refresh_per_second=4):
        for ip in targets:
            abuse, vt = get_intel(ip)
            
            # Decision Logic
            is_bad = (abuse > 25 or vt > 0)
            is_high_risk = (abuse > 80 or vt > 3)
            
            action = "[green]MONITORING[/]"
            if is_high_risk:
                action = apply_firewall_block(ip)
            
            verdict = "[bold red]MALICIOUS[/]" if is_bad else "[bold green]CLEAN[/]"
            
            table.add_row(ip, f"{abuse}%", str(vt), action, verdict)
            
            final_results.append({'ip': ip, 'abuse': abuse, 'vt': vt, 'is_bad': is_bad})
            time.sleep(15) # Stay under 4 requests/min limit

    # Generate Map after scan finishes
    console.print("[bold yellow][*] Scan Complete. Generating Visual Threat Map...[/]")
    generate_map(final_results)
    console.print("[bold green][+] DONE! Firewall Active. Map saved to threat_map.html[/]")

if __name__ == "__main__":
    main()
