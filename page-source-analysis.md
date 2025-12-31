1. check comments and links
2. check cookies
3. check framework artifacts (in comments, js, cookies, headers)
4. check favicon md5sum and check in OWASP online tool to recognize framework
```bash
curl https://example.com/images/favicon.ico | md5sum
```
https://owasp.org/www-community/favicons_database
5. check /sitemap.xml
6. check headers like X-Powered-By