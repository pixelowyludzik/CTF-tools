always try with anonymous login to ftp:
```bash
ftp ip port  
# try anonymous login  
hydra -l ftpuser -P wordlist.txt ftp://ip
```