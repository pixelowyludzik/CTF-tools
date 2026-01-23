```bash
ffuf -w /SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.example.thm" -u http://example.thm -mc 200  

ffuf -u http://example.thm/ -H "Host: FUZZ.example.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 19188 
# -fs parameter is for filtering length - exclude 19188 you need to test what value would be good for you
```

subfinder cheat sheet:
https://highon.coffee/blog/subfinder-cheat-sheet/

Vhosts
Virtual hosts discovery:
gobuster vhost -u http://TARGET_IP:PORT -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

query for certificate logs
ex. all dev subdomains :
```
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```