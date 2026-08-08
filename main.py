import os
import re
import time
from datetime import datetime

# --- CONFIGURATION DU SYSTEME SIEM (SOC) ---
LOG_FILE = "security_fortinet.log"
REPORT_FILE = "soc_daily_incident_report.txt"

# Seuils de détection
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW = 30  # en secondes

def generate_enterprise_logs():
    """Génère des logs réalistes contenant plusieurs types d'attaques cyber."""
    print("[*] Initialisation du flux de logs de l'entreprise...")
    current_date = datetime.now().strftime("%Y-%m-%d")
    
    logs = [
        f"{current_date} 10:00:01 IP 192.168.1.100 - LOGIN_SUCCESS admin_user\n",
        f"{current_date} 10:01:10 IP 45.33.22.11 - LOGIN_FAILED admin\n",
        f"{current_date} 10:01:12 IP 45.33.22.11 - LOGIN_FAILED admin\n",
        f"{current_date} 10:01:14 IP 45.33.22.11 - LOGIN_FAILED admin\n",
        f"{current_date} 10:01:16 IP 45.33.22.11 - LOGIN_FAILED admin\n",
        f"{current_date} 10:01:18 IP 45.33.22.11 - LOGIN_FAILED admin\n",  # Brute Force Alert Trigger
        f"{current_date} 10:02:45 IP 185.220.101.5 - HTTP_GET /index.php?id=1%20OR%201=1\n",  # SQL Injection Trigger
        f"{current_date} 10:03:12 IP 192.168.1.150 - LOGIN_SUCCESS user_01\n",
        f"{current_date} 10:04:20 IP 91.210.50.30 - HTTP_POST /login.php - <script>alert('XSS')</script>\n",  # XSS Trigger
        f"{current_date} 10:05:00 IP 185.220.101.5 - HTTP_GET /etc/passwd\n"  # Directory Traversal Trigger
    ]
    with open(LOG_FILE, "w") as f:
        f.writelines(logs)

def send_soc_notification(alert_type, ip, details):
    """Simule l'envoi d'un webhook d'alerte vers Slack/Discord et déclenche une notification."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[🔔 NOTIFICATION SENT] TO: SOC-TEAM-CHANNEL (via Webhook API)")
    print(f"=========================================================")
    print(f"🚨 CRITICAL ALERT - {alert_type}")
    print(f"⏰ Timestamp: {timestamp}")
    print(f"🌐 Attacker IP: {ip}")
    print(f"🛡️ Action Taken: IP Address blacklisted on Corporate Firewall")
    print(f"📝 Details: {details}")
    print(f"=========================================================\n")

def process_siem_engine():
    """Moteur SIEM principal pour l'analyse multi-威胁 et génération de rapports."""
    print(f"[*] Analyse SIEM en temps réel activée sur: {LOG_FILE}")
    
    if not os.path.exists(LOG_FILE):
        print("[-] Erreur: Flux de logs introuvable.")
        return

    failed_logins = {}
    incidents_detected = []

    # Regex patterns pour les signatures d'attaques
    sql_injection_pattern = re.compile(r"(OR%20|UNION%20SELECT|SELECT%20|'--|%27%20OR)", re.IGNORECASE)
    xss_pattern = re.compile(r"(<script>|javascript:|onerror=)", re.IGNORECASE)
    traversal_pattern = re.compile(r"(/etc/passwd|(\.\./)+|boot\.ini)", re.IGNORECASE)

    with open(LOG_FILE, "r") as f:
        for line in f:
            # Extraire l'IP et la date
            ip_match = re.search(r"IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            
            # 1. Détection des attaques Brute Force
            if "LOGIN_FAILED" in line:
                timestamp_str = line.split(" IP")[0]
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                
                if ip not in failed_logins:
                    failed_logins[ip] = []
                failed_logins[ip].append(timestamp)

                if len(failed_logins[ip]) >= BRUTE_FORCE_THRESHOLD:
                    time_diff = (timestamp - failed_logins[ip][-BRUTE_FORCE_THRESHOLD]).total_seconds()
                    if time_diff <= TIME_WINDOW:
                        details = f"Exceeded {BRUTE_FORCE_THRESHOLD} failed logins in {time_diff}s."
                        send_soc_notification("BRUTE FORCE DETECTED", ip, details)
                        incidents_detected.append((ip, "Brute Force", details))
                        failed_logins[ip] = []

            # 2. Détection d'injection SQL (SQLi)
            elif sql_injection_pattern.search(line):
                details = "Malicious SQL syntax detected in HTTP GET/POST parameters."
                send_soc_notification("SQL INJECTION ATTEMPT", ip, details)
                incidents_detected.append((ip, "SQL Injection", details))

            # 3. Détection d'attaques XSS
            elif xss_pattern.search(line):
                details = "Malicious JavaScript tags detected in HTTP payload."
                send_soc_notification("CROSS-SITE SCRIPTING (XSS)", ip, details)
                incidents_detected.append((ip, "XSS Attack", details))

            # 4. Détection de Directory Traversal
            elif traversal_pattern.search(line):
                details = "Unauthorized attempt to access system configuration files."
                send_soc_notification("DIRECTORY TRAVERSAL", ip, details)
                incidents_detected.append((ip, "Directory Traversal", details))

    # Génération du rapport SOC final
    with open(REPORT_FILE, "w") as rep:
        rep.write(f"==================================================\n")
        rep.write(f"          SOC DAILY INCIDENT REPORT              \n")
        rep.write(f"          Generated: {datetime.now()}\n")
        rep.write(f"==================================================\n\n")
        rep.write(f"[+] Total Incidents Blocked: {len(incidents_detected)}\n\n")
        for idx, (ip, attack, det) in enumerate(incidents_detected, 1):
            rep.write(f"Incident #{idx}:\n")
            rep.write(f" - Type: {attack}\n")
            rep.write(f" - Source IP: {ip}\n")
            rep.write(f" - Description: {det}\n")
            rep.write(f" ------------------------------------------\n")
    print(f"[+] Analyse terminée. Rapport SOC généré avec succès: {REPORT_FILE}")

if __name__ == "__main__":
    generate_enterprise_logs()
    time.sleep(1)
    process_siem_engine()
