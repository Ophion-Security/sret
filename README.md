# Salesforce Recon and Exploitation Toolkit

Salesforce Recon and Exploitation Toolkit

## Installation

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
$ python3 main.py -h    
usage: main.py [-h] [--token TOKEN] [--sid SID] [--uri URI] [--fwuid FWUID] [--app APP_DATA] [url]

SRET - Salesforce Recon and Exploitation Toolkit

positional arguments:
  url

options:
  -h, --help      show this help message and exit
  --token TOKEN   AURA token (Authenticated user)
  --sid SID       SID cookie (Authenticated user)
  --uri URI       Force specific AURA endpoint URI
  --fwuid FWUID   Force specific FWUID (default: wrongfwuid))
  --app APP_DATA  Force specific app (default: siteforce:loginApp2)
```

## References

* Announcement Blog - https://www.reconstation.io/blog/salesforce-recon-and-exploitation-toolkit-sret
* Salesforce Nuclei Template by Aaron Costello - https://github.com/projectdiscovery/nuclei-templates/blob/master/misconfiguration/salesforce-aura.yaml
* Salesforce Testing blog by 
Praveen Kanniah - https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-2-fuzz-exploit-eefae11ba5ae