# Report on TPOT Honeypot and VirusTotal Findings Across HK, UK, USA, and AUS Regions

This report consolidates findings from TPOT honeypot data and VirusTotal analysis of common Cowrie honeypot download files across the Hong Kong (HK), United Kingdom (UK), United States (USA), and Australia (AUS) regions between April and May, 2025.
It covers usernames, passwords, attack sources, operating systems, ports, CVEs, and downloaded files, providing insights into attack patterns, trends, and actionable recommendations for network protection. Additionally, it includes trend predictions based on observed patterns to anticipate future threats.

---

## Executive Summary

The TPOT honeypot data and VirusTotal analysis reveal a global pattern of cyberattacks targeting weak credentials, outdated systems, and specific vulnerabilities, with a focus on Linux and IoT devices. Commonalities across the four regions include heavy targeting of "root" and "admin" accounts, weak passwords like "123456", and ports 22 (SSH) and 5060 (SIP). The United States and Romania are primary attack sources, with botnet activity (e.g., "345gs5662d34") and malware like "mirai" and "multiverze" indicating coordinated campaigns. The data suggests a blend of legacy (e.g., CVE-2006-2369) and modern (e.g., CVE-2021-44228) vulnerability exploitation. Trend predictions point to increased IoT botnet activity, sophisticated credential attacks, and emerging vulnerabilities. Recommendations focus on securing credentials, patching systems, and monitoring key ports and IPs.

---

## Detailed Findings

### 1. [Usernames](./top10_usernames.md)
- **Commonalities**:
  - **root**: Top username in all regions (HK: 29,508; UK: 62,575; USA: 38,439; AUS: 25,720), reflecting default administrative account targeting.
  - **admin**, **sa**, **345gs5662d34**, **user**: Consistently in top 5–10, with "345gs5662d34" suggesting a specific botnet campaign.
- **Regional Variations**:
  - AUS shows multiple "admin" variations (e.g., aDmin, ADmiN), indicating case-sensitive brute-force attempts.
  - UK and USA include "git" and "hadoop", targeting development or big data environments.
- **Insight**: Attackers rely on brute-forcing default or generic usernames, with "345gs5662d34" indicating automated, coordinated attacks.

### 2. Passwords
- **Commonalities**:
  - **123456**: Most common password (HK: 8,045; UK: 10,549; USA: 11,757; AUS: 4,851), followed by **123**, **345gs5662d34**, **3245gs5662d34**, **password**, **admin**, **1234**, **12345**, **(empty)**, and **abc123**.
  - The "345gs5662d34" and "3245gs5662d34" strings align with the username pattern, suggesting linked credentials.
- **Regional Variations**:
  - USA has a high "(empty)" count (1,829), indicating attempts to exploit systems without passwords.
  - UK includes "NIALINTERNAL.COM" (703), possibly a campaign-specific password.
  - AUS shows unique passwords like "5201314" and "dragon".
- **Insight**: Weak and default passwords are heavily targeted, with "(empty)" attempts highlighting misconfigured systems.

### 3. Attacks by Country
- **Commonalities**:
  - **United States**: Top attack source (HK: 549,721; UK: 800,062; USA: 1,266,211; AUS: 755,017), likely due to large botnet infrastructure.
  - **Romania**, **China**, **United Kingdom**, **Russia**: Consistently in top 10, with Romania focusing on port 5060.
- **Regional Variations**:
  - Romania is significant in HK (424,947) and AUS (429,110).
  - South Africa stands out in UK (331,390).
  - Brazil is notable in USA (374,804).
- **Insight**: The USA’s dominance reflects its role as a hub for attack infrastructure, while Romania’s focus suggests specialized VoIP attacks.

### 4. OS Distribution
- **Commonalities**:
  - **Linux 2.2.x-3.x**: Dominant OS (HK: 3,317,952; UK: 2,971,687; USA: 3,989,951; AUS: 2,819,156), indicating legacy Linux targeting.
  - **Windows 7 or 8**, **Linux 3.11 and newer**, **Linux 2.2.x-3.x (barebone)**, **Windows NT kernel**: In top 5–10, showing broad OS coverage.
- **Regional Variations**:
  - UK targets "Windows XP" heavily (326,500).
  - HK and AUS include "Mac OS X".
  - USA includes "Linux 3.x".
- **Insight**: Attackers focus on outdated Linux systems and modern Windows, exploiting unpatched vulnerabilities.

### 5. Attacks by Country and Port
- **Commonalities**:
  - **Port 22 (SSH)**: Heavily targeted (e.g., USA/22: HK: 15,525; UK: 34,992; USA: 22,267; AUS: 12,363).
  - **Port 5060 (SIP)**: Major target, especially by Romania (HK: 398,894; UK: 340,448; USA: 193,766; AUS: 406,566).
  - **Port 23 (Telnet)**, **Port 80 (HTTP)**, **Port 5038**: Appear across regions, targeting remote access and VoIP.
- **Regional Variations**:
  - USA sees high VNC port activity (5900–5902).
  - AUS has significant China/15965 attacks (125,375).
  - Chile targets port 445 (SMB) in HK (127,807).
- **Insight**: SSH and VoIP services are universal targets, with regional port variations reflecting specific attack strategies.

### 6. CVEs
- **Commonalities**:
  - **CVE-2002-0013 CVE-2002-0012** (SNMP): Top 3 in all regions (HK: 2,949; UK: 2,434; USA: 4,682; AUS: 2,345).
  - **CVE-2006-2369** (VNC): Dominant in UK (170,143), USA (281,315), AUS (164,077), present in HK (1,284).
  - **CVE-2019-11500**, **CVE-2021-3449**, **CVE-2001-0414**, **CVE-2023-46604**, **CVE-2016-20016**: In top 10 across all regions.
- **Regional Variations**:
  - HK includes CVE-2002-1149 and CVE-2016-5696.
  - USA and AUS include CVE-2021-44228 (Log4j).
- **Insight**: Attackers exploit both legacy (SNMP, VNC) and modern (Log4j) vulnerabilities, targeting protocol weaknesses.

### 7. VirusTotal Analysis of Cowrie Download Files
- **Non-Malicious Files (8)**:
  - **File Type**: ASCII text, including a download script (`S=ip address; ...`) in six files, attempting to fetch payloads via `wget`, `curl`, or `ftpget`.
  - **Maliciousness**: 0/50–62 vendors flag as malicious, but the download script suggests an initial attack vector.
- **Malicious Files (14)**:
  - **File Types**: Bourne-Again shell scripts, ELF executables (MIPS, ARM, x86), OpenSSH RSA key, ASCII text with CRLF.
  - **Maliciousness**: 20–46/60–65 vendors flag as malicious.
  - **Threat Categories**: Trojans (10–23 vendors), downloaders (7–21), miners (5–16), PUA, hacktools.
  - **Threat Names**: multiverze, mirai/miraidownloader, medusa/geninst, xorddos/ddos, gikam, pvcyv, r002c0dcq25.
  - **Insight**: Malicious files target IoT/Linux systems, with botnets (mirai, multiverze) and miners exploiting weak credentials and ports 22/23.
- **VirusTotal Analysis Summary for Commoon Cowrie dowloaded files**:
  
 **Category**               | **Findings**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Non-Malicious Files (8)** | ASCII text; 6 files with download script (`wget`, `curl`, `ftpget`); 0/50–62 vendors flag malicious; likely initial attack vector. |
| **Malicious Files (14)**   | Shell scripts, ELF executables (MIPS, ARM, x86), SSH key; 20–46/60–65 vendors flag malicious; trojans, downloaders, miners dominate. |
| **Threat Categories**      | Trojans (10–23 vendors), downloaders (7–21), miners (5–16), PUA, hacktools; target IoT/Linux systems. |
| **Threat Names**           | multiverze, mirai/miraidownloader, medusa/geninst, xorddos/ddos, gikam, pvcyv, r002c0dcq25; indicate botnets, DDoS, mining. |
| **Integration with TPOT**  | Aligns with weak credentials ("root", "123456"), port 22/23 targeting, Linux focus; suggests botnet campaign (e.g., "345gs5662d34"). |
| **Key Insight**            | Botnets (mirai, multiverze) and miners exploit weak credentials and IoT/Linux systems; download scripts are precursors to malicious payloads. |
| **Recommendations**        | Secure SSH/Telnet, patch IoT/Linux, monitor ports 22/23/5060, detect trojans/miners, track botnet IPs. |






---

## Trend Predictions

Based on the observed patterns, the following trends are likely to emerge:

1. **Increased IoT Botnet Activity**:
   - The presence of "mirai" and "multiverze" in VirusTotal data, combined with port 23 (Telnet) and 5060 (SIP) targeting, suggests growing botnet campaigns targeting IoT devices. Expect more sophisticated variants leveraging weak credentials and unpatched devices.

2. **Sophisticated Credential Attacks**:
   - The consistent use of "345gs5662d34" and "3245gs5662d34" indicates coordinated botnet campaigns. Future attacks may use dynamically generated credentials or AI-driven brute-forcing to bypass detection.

3. **Exploitation of Emerging Vulnerabilities**:
   - The inclusion of CVE-2021-44228 (Log4j) in USA and AUS suggests attackers are quick to adopt new vulnerabilities. Expect increased targeting of recent CVEs, especially in widely used software like Apache or OpenSSL.

4. **Cryptocurrency Mining Surge**:
   - Miners (e.g., gikam, pvcyv) in VirusTotal data indicate a focus on resource hijacking. Rising cryptocurrency values may drive more mining malware targeting IoT and Linux systems.

5. **Regional Attack Source Diversification**:
   - While the USA and Romania dominate, emerging sources like South Africa (UK) and Brazil (USA) suggest attackers are diversifying infrastructure. New regions may emerge as attack hubs due to lax regulations or cheap hosting.

6. **Advanced Download Scripts**:
   - The download script (`S=ip address; ...`) in non-malicious files is versatile, using multiple tools (`wget`, `curl`, `busybox`). Future scripts may incorporate obfuscation or anti-analysis techniques to evade detection.

---

## Recommendations for Network Protection

To mitigate the threats identified in the TPOT and VirusTotal data, organizations should implement the following measures:

1. **Credential Security**:
   - **Enforce Strong Passwords**: Require complex, unique passwords for all accounts, especially "root" and "admin". Implement multi-factor authentication (MFA) for critical systems.
   - **Disable Default Accounts**: Remove or rename default accounts like "root", "admin", and "sa" to prevent brute-force attacks.
   - **Monitor Credential Patterns**: Use intrusion detection systems (IDS) to flag repeated attempts with credentials like "345gs5662d34" or "(empty)".

2. **System Hardening**:
   - **Patch Legacy Systems**: Update Linux 2.2.x-3.x and Windows XP/7/8 systems to mitigate vulnerabilities like CVE-2002-0013 and CVE-2006-2369.
   - **Secure IoT Devices**: Disable Telnet (port 23) and enforce SSH key-based authentication on port 22. Regularly update IoT firmware.
   - **Apply Modern Patches**: Prioritize patches for recent vulnerabilities like CVE-2021-44228 (Log4j) in software stacks.

3. **Network Security**:
   - **Firewall Rules**: Block or restrict traffic on high-risk ports (22, 23, 5060, 5900–5902, 15965) unless necessary. Use allowlists for trusted IPs.
   - **Intrusion Detection**: Deploy IDS/IPS to detect download attempts (e.g., `wget`, `curl`) and known botnet signatures (e.g., mirai, multiverze).
   - **IP Monitoring**: Monitor and block IPs from high-risk sources like the USA and Romania, especially for port 5060 traffic.

4. **Malware Defense**:
   - **Antivirus Deployment**: Use updated antivirus solutions to detect trojans (e.g., multiverze, xorddos), downloaders (e.g., medusa), and miners (e.g., gikam, pvcyv).
   - **Behavioral Monitoring**: Monitor for unusual CPU usage indicative of cryptocurrency mining or unauthorized SSH key installations.
   - **Sandbox Analysis**: Analyze suspicious downloads in a sandbox to identify payloads fetched by scripts like `S=ip address; ...`.

5. **Threat Intelligence**:
   - **Track Botnet Campaigns**: Monitor threat intelligence feeds for indicators related to "345gs5662d34", "mirai", and "multiverze" to anticipate attack patterns.
   - **Collaborate Globally**: Share IOCs (Indicators of Compromise) with regional cybersecurity communities to counter global botnet threats.

6. **Incident Response**:
   - **Rapid Response Plan**: Develop a plan to isolate compromised systems, especially those targeted via SSH or VoIP.
   - **Log Analysis**: Regularly review logs for brute-force attempts, port scanning, or download activity to detect early-stage attacks.

7. **Employee Training**:
   - Educate staff on recognizing phishing or social engineering attempts that may precede malware deployment.
   - Train IT teams on securing IoT devices and monitoring for botnet activity.

---
## Summary of the most critical patterns and regional variations.


| **Category**            | **HK**                                                                 | **UK**                                                                 | **USA**                                                                | **AUS**                                                                |
|-------------------------|-----------------------------------------------------------------------|-----------------------------------------------------------------------|-----------------------------------------------------------------------|-----------------------------------------------------------------------|
| **Top Username**        | root (29,508)                                                         | root (62,575)                                                         | root (38,439)                                                         | root (25,720)                                                         |
| **Other Key Usernames** | admin (4,586), sa (3,404), 345gs5662d34 (2,343)                       | admin (5,836), sa (4,801), 345gs5662d34 (2,325)                       | admin (6,606), 345gs5662d34 (2,320), user (2,012)                     | admin (5,042), sa (7,250), 345gs5662d34 (2,304)                       |
| **Username Notes**      | Common defaults; "345gs5662d34" suggests botnet activity              | Includes "git", "hadoop" for dev environments                         | Similar to UK; targets dev-related usernames                         | Many "admin" variations (e.g., aDmin, ADmiN)                          |
| **Top Password**        | 123456 (8,045)                                                       | 123456 (10,549)                                                      | 123456 (11,757)                                                      | 123456 (4,851)                                                       |
| **Other Key Passwords** | 123 (2,765), 345gs5662d34 (2,343), 3245gs5662d34 (2,338)             | 123 (4,391), 345gs5662d34 (2,325), 3245gs5662d34 (2,324)             | 123 (3,526), 3245gs5662d34 (2,323), 345gs5662d34 (2,320)             | 123 (2,395), 345gs5662d34 (2,304), 3245gs5662d34 (2,295)             |
| **Password Notes**      | Weak passwords prevalent; "(empty)" notable (830)                     | "NIALINTERNAL.COM" (703) unique; "(empty)" (969)                      | High "(empty)" count (1,829); weak passwords dominate                 | Unique passwords like "5201314" (190), "dragon" (176)                 |
| **Top Attack Country**  | United States (549,721)                                              | United States (800,062)                                              | United States (1,266,211)                                            | United States (755,017)                                              |
| **Other Key Countries** | Romania (424,947), France (371,705), China (174,510)                  | France (390,002), Romania (370,767), South Africa (331,390)           | Brazil (374,804), Romania (235,777), Russia (152,590)                 | Romania (429,110), France (359,484), China (300,394)                  |
| **Country Notes**       | Romania targets port 5060 heavily; Chile notable (128,422)            | South Africa significant for port 445; Indonesia present (68,395)     | Brazil prominent; Hong Kong (114,460) as source                       | High China activity on port 15965                                    |
| **Top OS**              | Linux 2.2.x-3.x (3,317,952)                                          | Linux 2.2.x-3.x (2,971,687)                                          | Linux 2.2.x-3.x (3,989,951)                                          | Linux 2.2.x-3.x (2,819,156)                                          |
| **Other Key OS**        | Windows NT kernel (566,636), Linux 3.11 and newer (533,245)           | Windows XP (326,500), Windows 7 or 8 (291,310)                        | Windows 7 or 8 (467,114), Linux 3.11 and newer (294,836)              | Windows 7 or 8 (348,943), Linux 2.2.x-3.x (barebone) (343,294)        |
| **OS Notes**            | Mac OS X in top 10 (10,778); legacy Linux focus                       | High Windows XP targeting (326,500); legacy systems                   | Linux 3.x (5,670) unique; modern and legacy systems                   | Mac OS X (13,974); focus on older Linux versions                     |
| **Top Country/Port**    | Romania/5060 (398,894)                                               | Romania/5060 (340,448)                                               | United States/5901 (255,560)                                         | Romania/5060 (406,566)                                               |
| **Other Key Ports**     | USA/22 (15,525), Chile/445 (127,807), France/22 (116,853)             | USA/5900 (121,107), France/22 (118,127), South Africa/445 (329,251)   | USA/5900 (175,920), Brazil/22 (117,441), Romania/5060 (193,766)       | USA/5900 (118,057), China/15965 (125,375), France/22 (116,169)        |
| **Port Notes**          | Port 5060 (SIP) and 22 (SSH) dominant; Chile’s 445 (SMB) unique       | High VNC (5900) and SMB (445) activity                               | VNC ports (5900-5902) prominent; SSH (22) consistent                  | Unique China/15965 attacks; SIP (5060) and SSH (22) focus             |
| **Top CVE**             | CVE-2002-0013 CVE-2002-0012 (2,949)                                  | CVE-2006-2369 (170,143)                                              | CVE-2006-2369 (281,315)                                              | CVE-2006-2369 (164,077)                                              |
| **Other Key CVEs**      | CVE-2002-1149 (1,448), CVE-2016-5696 (347)                           | CVE-2020-11910 (2,245), CVE-2002-0013 CVE-2002-0012 (2,434)          | CVE-2002-0013 CVE-2002-0012 (4,682), CVE-2021-44228 (103)            | CVE-2002-0013 CVE-2002-0012 (2,345), CVE-2021-44228 (92)             |
| **CVE Notes**           | Older SNMP and unique CVEs (e.g., CVE-2016-5696)                      | VNC (CVE-2006-2369) dominates; modern CVE-2020-11910                 | VNC and Log4j (CVE-2021-44228); mix of old and new vulnerabilities    | VNC and Log4j; older SNMP vulnerabilities                             |

### Key Insights
- **Weak Credentials**: "root", "admin", "123456", and "password" are prime targets, with "345gs5662d34" indicating botnet activity.
- **Attack Sources**: USA leads attacks; Romania targets port 5060; regional sources like South Africa (UK) and Brazil (USA) stand out.
- **Legacy Systems**: Linux 2.2.x-3.x and Windows XP are heavily targeted, showing exploitation of outdated systems.
- **Port Trends**: SSH (22) and SIP (5060) are universal; VNC (5900-5902) in USA and unique ports like 15965 in AUS are notable.
- **Vulnerabilities**: CVE-2006-2369 (VNC) dominates UK, USA, AUS; Log4j (CVE-2021-44228) in USA and AUS shows modern threats.

## Commonalitiies
The commonalities across the four regions highlight a global pattern of cyberattacks exploiting weak credentials, outdated systems, and specific vulnerabilities, particularly targeting SSH (port 22) and VoIP (port 5060) services. The consistent presence of the USA and Romania as attack sources, along with the "345gs5662d34" string, suggests coordinated botnet activity. Organizations should prioritize strong password policies, system patching (especially for legacy Linux and Windows systems), and securing key ports to mitigate these widespread threats.


| **Category**            | **Commonality Findings Across HK, UK, USA, AUS**                                                                 |
|-------------------------|---------------------------------------------------------------------------------------------------------------|
| **Usernames**           | **root** (top in all), **admin**, **sa**, **345gs5662d34**, **user** in top 10; default and generic accounts targeted. |
| **Passwords**           | **123456**, **123**, **345gs5662d34**, **3245gs5662d34**, **password**, **admin**, **1234**, **12345**, **(empty)**, **abc123** in top 10; weak passwords dominate. |
| **Attack Countries**    | **United States** (top in all), **Romania**, **China**, **United Kingdom**, **Russia** in top 10; USA and Romania lead. |
| **OS Distribution**     | **Linux 2.2.x-3.x** (top in all), **Windows 7 or 8**, **Linux 3.11 and newer**, **Linux 2.2.x-3.x (barebone)**, **Windows NT kernel**, **Linux 2.2.x-3.x (no timestamps)**, **Windows NT kernel 5.x**, **Linux 3.1-3.10** in top 10; legacy and modern systems targeted. |
| **Country/Port**        | **Port 22 (SSH)** (e.g., USA, France, China), **Port 5060 (SIP)** (esp. Romania), **Port 23 (Telnet)** (China), **Port 80 (HTTP)**, **Port 5038**; focus on remote access and VoIP. |
| **CVEs**                | **CVE-2002-0013 CVE-2002-0012**, **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517**, **CVE-2006-2369 (VNC)**, **CVE-2019-11500**, **CVE-2021-3449**, **CVE-2001-0414**, **CVE-2023-46604**, **CVE-2016-20016**; mix of old (SNMP, VNC) and newer vulnerabilities. |
| **Key Insight**         | Weak credentials, legacy systems, and specific ports (22, 5060) are universally targeted, with USA/Romania as key sources and "345gs5662d34" indicating botnet activity. |
| **Recommendation**      | Enforce strong passwords, patch legacy systems, secure ports 22/5060, and monitor USA/Romania IPs to counter coordinated attacks. |


## Conclusion

The TPOT honeypot and VirusTotal data reveal a sophisticated, global cyberattack landscape targeting weak credentials, legacy systems, and IoT devices across HK, UK, USA, and AUS. Common patterns include brute-forcing "root" and "admin" with passwords like "123456", heavy attacks from the USA and Romania, and exploitation of ports 22 and 5060. The VirusTotal findings confirm botnet activity (mirai, multiverze) and cryptocurrency mining, with download scripts acting as initial infection vectors. Predicted trends include increased IoT botnet sophistication, advanced credential attacks, and new vulnerability exploitation. By implementing strong credential policies, system patching, network monitoring, and malware defenses, organizations can significantly reduce their exposure to these threats.

