## Commonality  Across All Four Regions (HK, UK, USA, AUS)

Identifying the commonality findings across the HK, UK, USA, and AUS regions based on the TPOT honeypot data by analyzing the consistent patterns across usernames, passwords, attacks by country, OS distribution, attacks by country and port, and CVEs. 
The focus is on elements that appear prominently in all four regions, indicating shared attack characteristics.

### Commonality Findings Across All Four Regions (HK, UK, USA, AUS)

1. **Top Usernames**:
   - **root**: The most targeted username in all regions (HK: 29,508; UK: 62,575; USA: 38,439; AUS: 25,720), reflecting its status as a default administrative account.
   - **admin**: Second most common in all regions (HK: 4,586; UK: 5,836; USA: 6,606; AUS: 5,042), a frequent target due to its widespread use.
   - **sa**: Appears in the top 5 in all regions (HK: 3,404; UK: 4,801; USA: 1,937; AUS: 7,250), likely targeting SQL Server or system administrator accounts.
   - **345gs5662d34**: Consistently in the top 5 (HK: 2,343; UK: 2,325; USA: 2,320; AUS: 2,304), suggesting a specific botnet or automated attack campaign.
   - **user**: Present in the top 10 (HK: 1,898; UK: 1,912; USA: 2,012; AUS: 1,339), indicating attempts to exploit generic user accounts.

2. **Top Passwords**:
   - **123456**: The most common password across all regions (HK: 8,045; UK: 10,549; USA: 11,757; AUS: 4,851), highlighting the persistent use of weak passwords.
   - **123**: Second or third in all regions (HK: 2,765; UK: 4,391; USA: 3,526; AUS: 2,395), a simple and easily guessable password.
   - **345gs5662d34**: Appears in the top 5 (HK: 2,343; UK: 2,325; USA: 2,320; AUS: 2,304), aligning with the username pattern and suggesting coordinated credential attacks.
   - **3245gs5662d34**: Also in the top 5 (HK: 2,338; UK: 2,324; USA: 2,323; AUS: 2,295), further indicating a specific attack campaign.
   - **password**, **admin**, **1234**, **12345**, **(empty)**, **abc123**: These appear in the top 10 across all regions, emphasizing the reliance on default or weak passwords.

3. **Attacks by Country**:
   - **United States**: The top attack source in all regions (HK: 549,721; UK: 800,062; USA: 1,266,211; AUS: 755,017), likely due to its large internet infrastructure and botnet activity.
   - **Romania**: A top attacker in all regions (HK: 424,947; UK: 370,767; USA: 235,777; AUS: 429,110), often targeting specific ports like 5060.
   - **China**: Consistently in the top 5 (HK: 174,510; UK: 244,023; USA: 143,234; AUS: 300,394), indicating significant attack activity.
   - **United Kingdom**: Appears in the top 10 (HK: 85,087; UK: 88,293; USA: 81,530; AUS: 115,995), showing cross-regional attack patterns.
   - **Russia**: Present in the top 10 (HK: 50,196; UK: 102,478; USA: 152,590; AUS: 69,642), reflecting its role in global cyberattacks.

4. **OS Distribution**:
   - **Linux 2.2.x-3.x**: The most targeted OS in all regions (HK: 3,317,952; UK: 2,971,687; USA: 3,989,951; AUS: 2,819,156), indicating a focus on older Linux systems.
   - **Windows 7 or 8**: In the top 5 (HK: 251,751; UK: 291,310; USA: 467,114; AUS: 348,943), showing targeting of modern Windows systems.
   - **Linux 3.11 and newer**: In the top 5 (HK: 533,245; UK: 202,529; USA: 294,836; AUS: 183,684), reflecting attacks on newer Linux versions.
   - **Linux 2.2.x-3.x (barebone)**: In the top 5 (HK: 328,636; UK: 348,224; USA: 276,950; AUS: 343,294), targeting minimal Linux configurations.
   - **Windows NT kernel**: In the top 5 (HK: 566,636; UK: 103,997; USA: 139,270; AUS: 149,275), indicating broad Windows targeting.
   - **Linux 2.2.x-3.x (no timestamps)**, **Windows NT kernel 5.x**, **Linux 3.1-3.10**: Appear in the top 10 across all regions, showing consistent targeting of both Linux and Windows variants.

5. **Attacks by Country and Port**:
   - **Port 22 (SSH)**: Heavily targeted by multiple countries in all regions (e.g., USA, Romania, France, China), with counts like USA/22 (HK: 15,525; UK: 34,992; USA: 22,267; AUS: 12,363) and France/22 (HK: 116,853; UK: 118,127; AUS: 116,169).
   - **Port 5060 (SIP)**: A major target, especially from Romania (HK: 398,894; UK: 340,448; USA: 193,766; AUS: 406,566), indicating widespread VoIP exploitation attempts.
   - **Port 23 (Telnet)**: Targeted by China in all regions (HK: 3,162; UK: 3,327; USA: 2,643; AUS: 11,550), reflecting legacy protocol attacks.
   - **Port 80 (HTTP)**: Appears in top combinations (e.g., USA/80 in HK: 5,716; UK: 7,249; AUS: 629 via UK), showing web service targeting.
   - **Port 5038**: Targeted by Romania and USA in multiple regions (e.g., USA/5038 in HK: 13,354; AUS: 10,149), often linked to VoIP services.

6. **Top CVEs**:
   - **CVE-2002-0013 CVE-2002-0012**: SNMP vulnerabilities in the top 3 across all regions (HK: 2,949; UK: 2,434; USA: 4,682; AUS: 2,345), indicating persistent exploitation of older protocols.
   - **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517**: Also in the top 3 (HK: 1,892; UK: 1,646; USA: 4,055; AUS: 1,593), showing continued SNMP targeting.
   - **CVE-2006-2369**: A VNC vulnerability, prominent in UK (170,143), USA (281,315), and AUS (164,077), and present in HK (1,284), reflecting widespread VNC exploitation.
   - **CVE-2019-11500 CVE-2019-11500**: In the top 5 (HK: 512; UK: 519; USA: 511; AUS: 460), targeting specific system vulnerabilities.
   - **CVE-2021-3449 CVE-2021-3449**: In the top 10 (HK: 392; UK: 395; USA: 333; AUS: 330), indicating consistent OpenSSL vulnerability exploitation.
   - **CVE-2001-0414**, **CVE-2023-46604 CVE-2023-46604 CVE-2023-46604**, **CVE-2016-20016 CVE-2016-20016**: Appear in the top 10 across all regions, showing a mix of old and newer vulnerabilities.

### Summary of Commonalities
- **Weak Credentials**: Attackers consistently target default and weak credentials like "root", "admin", "sa", "123456", "123", "password", and "(empty)" across all regions, with "345gs5662d34" and "3245gs5662d34" indicating a specific botnet campaign.
- **Attack Sources**: The USA, Romania, China, UK, and Russia are consistent attack sources, with the USA leading due to its infrastructure scale and Romania focusing on port 5060.
- **Operating Systems**: Linux 2.2.x-3.x dominates, followed by Windows 7 or 8, Linux 3.11 and newer, and Windows NT kernel variants, showing a focus on both legacy and modern systems.
- **Targeted Ports**: Ports 22 (SSH) and 5060 (SIP) are universally targeted, with additional focus on ports 23 (Telnet), 80 (HTTP), and 5038 (VoIP-related), indicating attacks on remote access, VoIP, and web services.
- **Vulnerabilities**: Older vulnerabilities like CVE-2002-0013 and CVE-2002-0012 (SNMP) and CVE-2006-2369 (VNC) are heavily exploited, alongside newer ones like CVE-2021-3449 and CVE-2019-11500, showing a blend of legacy and modern attack vectors.

### Conclusion
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
