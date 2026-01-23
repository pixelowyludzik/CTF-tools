```bash
# aggressive scanning
 <IP>  
nmap -p- -sS -sV -T4 -A -sC <IP>
nmap -A -p- [Machine_IP] -T5 -Pn 
# safer
nmap -sV
nmap -T2
nmap -T1
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
https://highon.coffee/blog/nmap-cheat-sheet/

bypassing firewall
Hide a scan with decoys  `-D DECOY1_IP1,DECOY_IP2,ME`
Hide a scan with random decoys `-D RND,RND,ME`
Use an HTTP/SOCKS4 proxy to relay connections `--proxies PROXY_URL`
Spoof source MAC address `--spoof-mac MAC_ADDRESS`
Spoof source IP address `-S IP_ADDRESS`
Use a specific source port number `-g PORT_NUM` or `--source-port PORT_NUM`
Fragment IP data into 8 bytes `-f`
Fragment IP data into 16 bytes `-ff`
Fragment packets with given MTU `--mtu VALUE`
Specify packet length `--data-length NUM`

Set IP time-to-live field `--ttl VALUE`
Send packets with specified IP options `--ip-options OPTIONS`
Send packets with a wrong TCP/UDP checksum `--badsum`


port forwarding
`ncat -lvnp 443 -c "ncat TARGET_SERVER 25"`
ex.
port 80 is blocked on server, 
port 8008 is open
we can run command on server
ncat -lvnp 8008 -c "ncat TARGET_SERVER 80"
and open website on port 8008 instead 80