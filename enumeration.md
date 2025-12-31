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
```

