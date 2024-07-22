# SONiC-FQDN-Port_ACLs
Intern - Mark Glinberg

Mentor - Jonathan Gorel

Manager - John Marquiss

## Description

This project aims to add functionality to SONiC, such that you can abstract creating ACL_RULES based on domain names, rather than IPs. Details can be found in this [design doc](https://microsoft-my.sharepoint.com/:w:/p/t-mglinberg/Ebvl6HJ0W89Hs2ZuAmPDkiYBtTJn3yFt92AJRpQe8_dlhA?e=WhhaJG) (accessible only by MSFT employees).

### Testing

For unit tests, all of the subprocess calls need to be commented and all of the substitute lines that read dummy json files need to be uncommented. For get_ip_addresses() specifically, the TestUpdate class requires the use of the dummy nslookup.json file, while all the rest of the tests can use the socket version of the code.
