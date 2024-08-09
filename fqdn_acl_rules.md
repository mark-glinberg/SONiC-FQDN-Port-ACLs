# FQDN ACL Rules

## Revision

| **Rev**   | **Date**  | **Authors**   | **Change Description**|
| --------- | --------- | ------------- | --------------------- |
| 1         |           |Jonathan Gorel <br> Mark Glinberg |   Initial Version     |
## Scope

## Definitions/Abbreviations

| **Term**  | **Meaning**|
|---------- |------------|
|ACL        | Access Control List   |
|ACL_RULE   | A rule within an ACL that governs traffic between one or two IP addresses over any number of ports|
|FQDN       | Fully-Qualified Domain Name |
|FQDN_ACL_RULE_TEMPLATE  |   Template for creating an ACL_RULE from a given FQDN |

The term template or FQDN_TEMPLATE can be used in place of FQDN_ACL_RULE_TEMPLATE. The term RULE or rule can be used in place of ACL_RULE.
## Overview

Currently, ACLs are made up of ACL_RULEs which whitelist or blacklist certain IPs and ports from one another. ACL_RULEs natively don't support FQDNs, as they need to have IP addresses to function properly.

This feature resolves this issue by introducing a new type of entry called a FQDN_ACL_RULE_TEMPLATE, which grealty resembles an ACL_RULE except that it also can reference a FQDN as well as an IP Address. These templates, once created, are then programatically translated into ACL_RULEs after their domains are resolved via the DNS.

## Requirements

## Architecture Design

### Rule Name Design

This feature needs certain pieces of information from each ACL_RULE that was generated from a FQDN_ACL_RULE_TEMPLATE. The only customizable field to put this information in is the ACL_RULE_NAME, which will allow the feature to sort through the existing ACL_RULEs properly and improve readibility for end users.

#### Rule Name Components

The rule name is made up of the following 5 components, each of which will be delimited by an underscore (`_`).

| **Prefix** | **Endpoint** | **Domain** | **Template Name** | **Rule Number** |
| ---------- | ------------ | ---------- | ----------------- | --------------- |
| This will distinguish a regular rule from a programatically generated one. The prefix is `"FQDN_PREFIX"`.| Since each ACL_RULE can have a source and destination IP address, it needs to be clear which of those came from resolving an FQDN. As such, this flag will either be `"SRC"` or `"DST"` to denote that.| This portion will just be the first 7 characters of the domain name that the ACL_RULE was generated from. | This  will be the name of the template that generated the ACL_RULE. | The number will distinguish ACL_RULEs from one another if they share the same template, as one domain can resolve to multiple IPs, and thus create multiple rules.

*The rule number is not currently guaranteed to be contiguous due to the use of sets in the code. As such, there might only be two rules, but one has the number `1` and one has the number `3`.

### YANG Model Design

The [sonic-fqdn-acl-template.yang](sonic-fqdn-acl-template.yang) model was designed based off the [sonic-acl.yang](sonic-acl.yang) model, with a few modifications. The new model is generated based off the old model using the [fqdn_yang.py](fqdn_yang.py) script. This script:

- imports sonic-acl
- replaces RULE_NAME with TEMPLATE_NAME, which doesn't allow underscores
- changes the key for ACL_RULE to just be the TEMPLATE_NAME
- enforces that ACL_TABLE_NAME is a mandatory leaf
- adds a new choice statement for a SRC_DOMAIN and DST_DOMAIN leaf
- modifies the src_dst_address statement to account for the new domain leaves
- deletes the extra containers (ACL_TABLE and ACL_TABLE_TYPE)
- resolves any mention of "sonic-acl" or "ACL_RULE" to "sonic-fqdn-acl-template" or "FQDN_ACL_RULE_TEMPLATE"

The use of a script to generate a new YANG file is done in order to avoid redundant definitions, so that if the [sonic-acl.yang](sonic-acl.yang) file is updated, then the [sonic-fqdn-acl-template.yang](sonic-fqdn-acl-template.yang) file wouldn't need to be touched since it's always generated based on the original. YANG keywords like "grouping", "uses", and "augment" proved to not work fully within SONiC or couldn't replicate the functionality needed in order to import the definitions laid out in [sonic-acl.yang](sonic-acl.yang) over to [sonic-fqdn-acl-template.yang](sonic-fqdn-acl-template.yang).


## Notes for Jon

- [fqdn_setup.sh](fqdn_setup.sh) runs [fqdn_yang.py](fqdn_yang.py) and then schedules [fqdn.py](fqdn.py) as a cron job to run every 10 minutes
- [fqdn_metrics.py](fqdn_metrics.py) will run in SONiC to stress test the script and output metrics as a table and csv. This runs perfectly in SONiC
- [fqdn_test.py] is set up to run locally to test the script. It requires that the subprocess calls throughout the fqdn.py script are commented out, and instead that the methods read from dummy files that the test script creates (all of this code is commented right above the subprocess calls)