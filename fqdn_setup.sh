#!/bin/bash

sudo python ~/fqdn_yang.py

(crontab -l 2>/dev/null; echo "*/10 * * * * sudo python ~/fqdn.py")| crontab -