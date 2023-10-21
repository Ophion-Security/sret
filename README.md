# Salesforce Recon and Exploitation Toolkit

Salesforce Recon and Exploitation Toolkit

## Installation

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
usage: main.py [-h] [-t TOKEN] [-s SID] [-u URI] [-f FWUID] [-a APP_DATA] [-d] [-o DUMP_OUTPUT] [url]

SRET - Salesforce Recon and Exploitation Toolkit

positional arguments:
  url

options:
  -h, --help            show this help message and exit
  -t TOKEN, --token TOKEN
                        AURA token (Authenticated user)
  -s SID, --sid SID     SID cookie (Authenticated user)
  -u URI, --uri URI     Force specific AURA endpoint URI
  -f FWUID, --fwuid FWUID
                        Force specific FWUID (default: wrongfwuid))
  -a APP_DATA, --app APP_DATA
                        Force app (default: will try siteforce:loginApp2, one:one)
  -d, --dump-records    Dump all readable objects (Default: <OUTPUT_DIRECTORY>/<OBJECT>/<RECORD_ID>.json).
  -o DUMP_OUTPUT, --dump-output DUMP_OUTPUT
                        Dump output directory (Default: ./output_<TIMESTAMP>).
```

## Features

[x] Unauthenticated tests
[x] Authenticated tests
[x] Try to find AURA URI  
[x] Try to find App name  
[x] Try to find FWUID  
[x] Find readable standards (wordlist) and custom objects  
[x] Find writable standards (wordlist) and custom objects  
[x] Dump records  
[ ] Dump documents (ContentDocument, ...)  
[ ] Get collab feed (Maintenance of `get_collab_feeds` method)  
[ ] Search object (Maintenance of `search_object` method)

## References

* Announcement Blog - https://www.reconstation.io/blog/salesforce-recon-and-exploitation-toolkit-sret
* Salesforce Nuclei Template by Aaron Costello - https://github.com/projectdiscovery/nuclei-templates/blob/master/misconfiguration/salesforce-aura.yaml
* Salesforce Testing blog by 
Praveen Kanniah - https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-2-fuzz-exploit-eefae11ba5ae