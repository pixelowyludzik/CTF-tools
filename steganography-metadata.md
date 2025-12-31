```bash
exiftool file.jpg  
steghide info file.jpg  
steghide --extract -sf file.jpg
```

### broken files
```bash
# edit magic bytes to match extension:  
hexeditor file.jpg
```