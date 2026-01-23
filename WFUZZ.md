d```bash
# example - generating numbers as wordlist:  
seq -w 0 99 > numery.txt  
wfuzz -c -u http://TARGET_IP/static/FUZZ -w numery.txt  
  
wfuzz -c -z file,/media/sf_wordlists/SecLists-master/Discovery/Web-Content/api/objects.txt -X POST --hc 404,400 http://TARGET_IP/api/items\?FUZZ\=test
```

FFUF
examples of fuzzing api parameters
```bash
$ ffuf -u 'http://MACHINE_IP/sqli-labs/Less-1/?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fw 39  
$ ffuf -u 'http://MACHINE_IP/sqli-labs/Less-1/?FUZZ=1' -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -fw 39

# with generating numbers:
ruby -e '(0..255).each{|i| puts i}' | ffuf -u 'http://MACHINE_IP/sqli-labs/Less-1/?id=FUZZ' -c -w - -fw 33

# brute force:
ffuf -u http://MACHINE_IP/sqli-labs/Less-11/ -c -w /usr/share/seclists/Passwords/Leaked-Databases/hak5.txt -X POST -d 'uname=Dummy&passwd=FUZZ&submit=Submit' -fs 1435 -H 'Content-Type: application/x-www-form-urlencoded'
```