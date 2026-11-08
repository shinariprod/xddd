## Contents

- [Networking](#networking)
  - [Common Ports and Protocols](#common-ports-and-protocols)
- [Security Concepts](#security-concepts)
- [SOC & Tools](#soc--tools)
  - [EDR, IDS/IPS, Firewalls, Proxies](#edr-idsips-firewalls-proxies)
  - [Alert Triage](#alert-triage)
- [Logs & Analysis](#logs--analysis)
- [Incident Response & Frameworks](#incident-response--frameworks)
- [Windows & Infrastructure](#windows--infrastructure)
  - [Windows Processes, Services, and Registry](#windows-processes-services-and-registry)
  - [Active Directory (AD)](#active-directory-ad)
  - [Phishing Email and Header Analysis](#phishing-email-and-header-analysis)

---

## Networking

*   **OSI and TCP/IP models**
    *   **OSI Model** has 7 layers. It's a theoretical framework. The layers are: **Physical**(Sends bits on a cable or by radio), **Data Link**(Moves frames inside one local network), **Network**(Finds the path between networks), **Transport**(Moves data between two programs), **Session**, **Presentation**(Changes the format of data), **Application**(Programs talk to the network).
    *   **TCP/IP Model** has 4 layers. It's used in the real world. The layers are: Network Access, Internet, Transport, Application.
*   **TCP vs UDP and the three-way handshake**
    *   **TCP** is reliable(релайэбл) and connection-oriented(ориэнтид). It guarantees data delivery (used for web, email).
    *   **UDP** is fast and connectionless. It sends data without checking if it arrived (used for video streaming, gaming).
    *   **Three-Way Handshake** is how TCP connects:
        1.  **SYN:** Client sends a synchronization request.
        2.  **SYN-ACK:** Server responds with synchronization and acknowledgment.
        3.  **ACK:** Client sends a final acknowledgment. Connection is established.

### Common Ports and Protocols
*   **SSH (22):** Secure Shell for remote access.
*   **DNS (53):** Domain Name System for name resolution.
*   **HTTP (80) / HTTPS (443):** Web browsing (HTTPS adds TLS/SSL encryption).
*   **Keberos 88:** Auth.

**DNS (Domain Name System)**

DNS translates human-friendly domain names (like `google.com`) into IP (like `142.250.190.46`) that computers understand.

**Dns Record Type**

| Record | Meaning |
|---|---|
| A / AAAA | IPv4 or IPv6 |
| MX | mail server |
| NS | DNS server of the zone |
| TXT | text, often SPF or DKIM |
| CNAME | another name |
| PTR | name for an IP. Reverse DNS |

Attacks: spoofing (fake answer), cache poisoning, tunneling (data inside DNS), amplification (open resolver makes DDoS bigger), hijacking (stolen domain). A lookalike domain is typosquatting.


**DHCP** is a protocol for the automatic assignment of IP; It provides an IP, subnet mask, gateway, and DNS settings.

The **DORA** process:
* **Discover** — the client searches for a server (broadcast)
* **Offer** — the server offers an IP address
* **Request** — the client makes a selection
* **ACK** — acknowledgment

**ARP (Address Resolution Protocol)** maps IP to MAC within a local network 

How it works:
* **ARP Request** — a broadcast: "Who has the IP 192.168.0.2?"
* **ARP Reply** — the owner responds directly: "That’s me; my MAC address is A5:22:98:5C:24:93."
* **Subsequent** packets are then sent directly using the MAC address.

**Subnetting, NAT, private vs public IPs**

*   **Subnetting:** Dividing a large network into smaller, manageable sub-networks to improve performance and security.
*   **Public IP:** A unique IP address used to connect to the global Internet.
*   **Private IP:** Used inside a local network. It cannot be routed on the Internet.
*   **NAT (Network Address Translation):** A technology that translates private IPs into a single public IP so local devices can access the Internet.

**SNAT** — an internal private IP is replaced by the router’s public IP

**DNAT** — a public IP is redirected to an internal server’s IP

**PAT (NAT Overload)** — an extension of SNAT that also modifies the port.

**Static NAT** — a one-to-one mapping between an internal IP and an external IP. **Dynamic NAT** — external IP are drawn from a pool.

## Security Concepts

**CIA triad**
  *   **Confidentiality:** Keeping data secret (only authorized people can see it, e.g., using encryption).
  *   **Integrity:** Keeping data accurate and unchanged. (e.g., using hashing).
  *   **Availability:** Ensuring data and systems are accessible when needed.

**Threat, vulnerability, and risk**
  *   **Vulnerability:** A weakness in a system (like a missing security patch).
  *   **Threat:** A danger that can exploit a vulnerability (like a hacker or malware).
  *   **Risk:** The probability and impact of a threat exploiting a vulnerability (Risk = Threat × Vulnerability).

**Encryption, hashing, and encoding**
  *   **Encryption:** Scrambles data to keep it secret. It can be reversed with a key (two-way).
  *   **Hashing:** Creates a unique, fixed-size fingerprint of data. It cannot be reversed (one-way). Used to verify integrity.
  *   **Encoding:** Changes data format so different systems can read it (e.g., Base64). It is **not** for security, as it requires no key to decode.
 
**Authentication vs authorization, MFA**
  *   **Authentication:** Verifying **who you are** (e.g., username and password).
  *   **Authorization:** Verifying **what you are allowed to do** (e.g., access rights, admin privileges).
  *   **MFA (Multi-Factor Authentication):** Requiring two or more pieces of evidence to log in: something you know (password), something you have (phone), or something you are (fingerprint).

**Common attack types**
  *   **Phishing:** Fake emails to steal sensitive information.
  *   **Malware:** Malicious software (viruses, ransomware, spyware).
  *   **DDoS (Distributed Denial of Service):** Flooding a server with traffic to crash it.
  *   **SQL Injection:** Injecting malicious code into a database query to steal or modify data.
  *   **Ransomware:** Encrypting user data and demanding money for the decryption key.

## SOC & Tools


### EDR, IDS/IPS, Firewalls, Proxies
*   **SIEM** Collects and correlates security events from across the entire(инта́йэр) infrastructure.
*   **Firewall:** is a network traffic filtering system. allow or block by IP, port, protocol, sometimes content.
*   **IDS (Intrusion Detection System):** detect and alert. Does not block. 2 type nids, hids
*   **IPS (Intrusion Prevention System):** monitors traffic and automatically(отэмэ́тикли) blocks threats(сфрэтс).
*   **Proxy:** A proxy acts as an intermediary between a client and a server, forwarding requests and returning responses on the client's behalf.
*   **EDR (Endpoint Detection and Response):** Detects suspicious activity on the endpoint, collects telemetry and helps investigate incidents. Can isolate the host or terminate a malicious(мэ-ЛИ-шэс) process
*   **EPP** Prevention of infection on endpoints.
*   **XDR** Combines data from different sources for better detection
*   **SOAR** Orchestration and automation of response processes: playbooks, automatic enrichment of IOC, creation of tickets, execution of actions in EDR/EPP, notifications

### Alert Triage
*   The process of **sorting and prioritizing security alerts**. Analysts verify the context, check relevant logs, determine if an alert is a True Positive (real threat) or False Positive (false alarm), and assign a severity level.

---

## Logs & Analysis

*   **Windows Event IDs**
    *   `4624`: Successful logon.
    *   `4625`: Failed logon.
    *   `4720`: A user account was created.
    *   `7045`: A new service was installed (often used by attackers for persistence).
*   **Web server log analysis**
    *   When analyzing web logs (Apache/Nginx), look for **HTTP status codes**:
        *   `200 OK`: Request succeeded.
        *   `404 Not Found`: Attacker might be scanning for directories.
        *   `500 Internal Server Error`: Could indicate an exploitation attempt.
    *   Look for suspicious characters in URLs like `' OR 1=1` (SQLi) or `<script>` (XSS).

## Incident Response & Frameworks

**Incident response lifecycle (NIST)**
  * **Preparation:** Setting up tools and policies.
  * **Detection & Analysis:** Identifying and confirming security incidents.
  * **Containment, Eradication, & Recovery:** Stopping the attack, removing the threat, and restoring systems.
  * **Post-Incident Activity:** Learning lessons to improve future security.

**Indicators of Compromise (IoC) vs Indicators of Attack (IoA)**
  *   **IoC (Evidence):** Compromise indicators: IP, domains, URL, hashes, certificates, mutex.
  *   **IoA (Behavior):** helps to detect an attack at an early stage

**MITRE ATT&CK**
Knowledge base about how attackers really act. In matrix form:

* **Tactic** - why the attacker makes a step (Initial Access, Credential Access).
* **Technique** - how exactly (Phishing, Valid Accounts).
* **Sub-technique** - a specific version of the technique.

**Why use ATT&CK:**
* **Standardized Language:** Replaces vague alerts with exact technique IDs (e.g., T1059) across SOC, IR, and Hunting.
* **Faster Triage:** Reveals the attacker's phase and intent instead of isolated, contextless IOCs.
* **Gap Analysis:** Maps detection coverage to pinpoint blind spots.
* **Risk-Based Focus:** Prioritizes security enhancements based on your specific threat profile.

**Cyber Kill Chain**
A model by Lockheed Martin showing the **stages of a cyberattack**:
    1.  Reconnaissance -> 2. Weaponization -> 3. Delivery -> 4. Exploitation -> 5. Installation -> 6. Command & Control (C2) -> 7. Actions on Objectives.

The main meaning of Kill Chain is to "break the chain" as soon as possible.

**Threat intelligence and OSINT tools**
*   **Threat Intelligence:** Information used to understand the capabilities and motives of cybercriminals.
*   **OSINT (Open Source Intelligence):** Data collected from publicly available sources.
*   **Common Tools:** VirusTotal (file and URL analysis), Shodan (search engine for internet-connected devices), AbuseIPDB (reputation tracking for IP addresses).


## Windows & Infrastructure

### Windows Processes, Services, and Registry
*   **Process:** A running program (e.g., `explorer.exe`).
*   **Service:** A program that runs in the background without user interaction (e.g., Windows Update).
*   **Registry:** A centralized database where Windows stores system, hardware, and user configuration settings.

### Active Directory (AD)
A Microsoft service used to **manage objects like users, computers, and access permissions** inside a corporate network. It uses a centralized database, and the **Domain Controller (DC)** is the server that runs it.

* **Object directory** — a unified database of employees, computers, groups, and organizational units (OUs).
* **Authentication** — verification of user and device identities (Kerberos, NTLM).
* **Authorization** — management of access to resources via security groups.
* **Group Policy (GPO)** — centralized configuration of OS, software, and security policies.

### Phishing Email and Header Analysis
*   Check the **Sender Address** (look for typosquatting like `sec-ur-ity.com`).
*   Analyze the **Email Header**: Check `Authentication-Results` like **SPF, DKIM, and DMARC** to see if the email is spoofed.
*   Look for urgent language, suspicious links, and unexpected attachments.
