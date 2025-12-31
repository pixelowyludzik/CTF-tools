```bash
# example - generating numbers as wordlist:  
seq -w 0 99 > numery.txt  
wfuzz -c -u http://TARGET_IP/static/FUZZ -w numery.txt  
  
wfuzz -c -z file,/media/sf_wordlists/SecLists-master/Discovery/Web-Content/api/objects.txt -X POST --hc 404,400 http://TARGET_IP/api/items\?FUZZ\=test
```