```commands:
ffuf -w /wordlist/path  -u http://TARGET_IP/FUZZ

dirb http://TARGET_IP/ /wordlist/path

gobuster dir --url http://TARGET_IP/ -w /wordlist/path

feroxbuster -u 'http://TARGET_IP/' -w /wordlist/path

```
good wordlists:
1. /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
2. /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
3. /media/sf_wordlists/SecLists-master/Discovery/Web-Content/raft-medium-files.txt
4. /media/sf_wordlists/SecLists-master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
5. /media/sf_wordlists/SecLists-master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
6. use -x parameter:
```
asp,aspx,phar,php,php3,php4,php5,phtml,phtm,shtm,shtml,jhtml,txt,pl,jsp,cfm,cfml,py,rb,cfg,conf,ini,env,log,zip,rar,7z,tar,tar.gz,tgz,gz,bak,old,backup,swp,tmp,sql,db,sqlite,sqlite3,pdf,doc,docx,xls,xlsx,json,xml,yml,yaml,md,inc,dist,example,orig,save,lock
```


