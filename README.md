# SONiC-FQDN-Port_ACLs
Intern - Mark Glinberg

Mentor - Jonathan Gorel

Manager - John Marquiss

## Description

This project aims to add functionality to SONiC, such that you can abstract creating ACL_RULES based on domain names, rather than IPs. Details can be found in this [design doc](https://microsoft-my.sharepoint.com/:w:/p/t-mglinberg/Ebvl6HJ0W89Hs2ZuAmPDkiYBtTJn3yFt92AJRpQe8_dlhA?e=WhhaJG) (accessible only by MSFT employees).

### Files

- fqdn.py — script for translating FQDN Templates into ACL Rules
- fqdn_yang.py — script for creating sonic-fqqn-acl-template.yang from sonic-acl.yang
- fqdn_setup.sh — shell script to run fqdn_yang.py and create cron job out of fqdn.py
- fqdn_metrics.py — script that runs fqdn.py with multiple different conditions to get load metrics
- fqdn_test.py — unittest script for the main script (need to comment certain things in fqdn.py - see below)
- fqdn.pseudo — pseudocode that mostly reflects the code in fqdn.py
- sonic-fqdn-acl-template.yang — new yang file used for fqdn templates
- sonic-acl.yang — original sonic acl yang file

### Testing

For unit tests, all of the subprocess calls need to be commented and all of the substitute lines that read dummy json files need to be uncommented. For get_ip_addresses() specifically, the TestUpdate Test Case requires the use of the dummy nslookup.json file, while all the rest of the tests can use the socket version of the code.
