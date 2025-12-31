```bash
nmap -p- -sS -sC -sV -A -T4 <IP>  
nmap -p- -sS -sV -T4 -A -sC <IP>
```
types of scan:
1. ARP Scan
   `sudo nmap -PR -sn MACHINE_IP/24`
2. ICMP Echo Scan
   `sudo nmap -PE -sn MACHINE_IP/24`
3. ICMP Timestamp Scan
   `sudo nmap -PP -sn MACHINE_IP/24`
4. ICMP Address Mask Scan
   `sudo nmap -PM -sn MACHINE_IP/24`
5. TCP SYN Ping Scan
   `sudo nmap -PS22,80,443 -sn MACHINE_IP/30`
6. TCP ACK Ping Scan
   `sudo nmap -PA22,80,443 -sn MACHINE_IP/30`
7. UDP Ping Scan
   sudo nmap -PU53,161,162 -sn MACHINE_IP/30`
