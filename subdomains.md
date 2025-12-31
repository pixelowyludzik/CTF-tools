```bash
ffuf -w /SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.example.thm" -u http://example.thm -mc 200  

ffuf -u http://example.thm/ -H "Host: FUZZ.example.thm" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 19188 
# -fs parameter is for filtering length - exclude 19188 you need to test what value would be good for you
```
