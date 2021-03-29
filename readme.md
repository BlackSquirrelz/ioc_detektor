# IOC Detektor

Too lazy to search each log file for known IOC's?

---

Flags: 

 - -a ALL
 - -o OUTPUT
- -d ROOT_DIRECTORY
- -f FILE
- -ip IP
- -re REGEX
- -s SHELLS
- -ha HASHES
- -? HELP

---

### Usage:

use ```-f``` to scan a single file, or ```-d``` to scan a directory.

### Implemented:

- Check IP addresses in a log file against known IOCs'
```python3 ioc_scanner.py -f <file> -ip```

### Planned:

- Check Regex  in a log file against known IOCs'
```python3 ioc_scanner.py -f <file> -ip```
  
- Check Hashes in a log file against known IOCs'
```python3 ioc_scanner.py -f <file> -ip```
  
- Check paths  in a log file against known IOCs'
```python3 ioc_scanner.py -f <file> -ip```
  


  