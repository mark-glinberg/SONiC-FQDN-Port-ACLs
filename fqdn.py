import json
import subprocess
import hashlib
import ipaddress

PREFIX = "FQDN_RULE_"

def createPatch(path, op, template=None, ip=None, src_dst=None):
    """Creates a patch entry for the Generic Config Updater (GCU)

    Args:
        path ("String"): path of the rule to patch (<TABLE_NAME>|<RULE_NAME>)
        op ("String"): "add" or "remove"
        template ("Dict", optional): template of the rule if op="add". Defaults to None
        ip ("String", optional): ip of the rule if op="add". Defaults to None.
        ip ("String", optional): whether the domain is the "SRC" or "DST" for the rule traffic if op="add". Defaults to None.

    Returns:
        dict: the patch for that rule to be read by the GCU
    """
    patch = {}
    patch["op"] = op
    patch["path"] = "/ACL_RULE/" + path
    if op == "add":
        rule = dict(template)

        address, mask = ip.split("/")
        ipaddress_obj = ipaddress.ip_address(address)
        
        if ipaddress_obj.version == 4:
            ip_type = "IP"
        else:
            ip_type = "IPV6"

        rule[src_dst + "_" + ip_type] = ip

        patch["value"] = rule
    return patch

def getExistingRules():
    """Queries SONiC for all existing ACL_RULES,
    filters out the non-fqdn rules (keeps only auto-generated ones),
    and returns all generated rules in a sorted, nested dictionary

    Returns:
        dict: nested mapping of rules with keys: table -> domain -> hash -> list of rules with matching templates but different ips
    """
    rules = {}

    # sonic_out = subprocess.run("sonic-cfggen -d --var-json ACL_RULE", shell=True, capture_output=True, text=True)
    # existing_rules = json.loads(sonic_out.stdout)
    with open("rules.json") as f: # Need to replace with the above commands
        existing_rules = json.load(f)

    for key, rule in existing_rules.items():
        table, name = key.split("|")
        if PREFIX == name[:len(PREFIX)]:
            pre, fix, src_dst, domain, template_name, number = name.split("_")

            value = {}
            value["number"] = int(number)
            value["src_dst"] = src_dst

            ip_types = ["IP", "IPV6"]
            
            for ip_type in ip_types:
                key = src_dst + "_" + ip_type
                if key in rule:
                    value["ip"] = rule[key]
                    rule.pop(key)
                    break

            value["rule"] = rule
            
            if table not in rules:
                rules[table] = {}

            if src_dst not in rules[table]:
                rules[table][src_dst] = {}

            if domain not in rules[table][src_dst]:
                rules[table][src_dst][domain] = {}

            if template_name not in rules[table][src_dst][domain]:
                rules[table][src_dst][domain][template_name] = []

            rules[table][src_dst][domain][template_name].append(value)
    
    return rules
rules = getExistingRules()

with open("out.json", "w") as f:
    json.dump(rules, f, indent=4)

def getTemplates():
    """Queries SONiC for all existing templates and returns them as a list

    Returns:
        list: dictionaries of all existing templates
    """
    # sonic_out = subprocess.run("sonic-cfggen -d --var-json FQDN_ACL_RULE_TEMPLATE", shell=True, capture_output=True, text=True)
    # templates = json.loads(sonic_out.stdout)
    with open("templates.json") as f: # need to replace with the above commands
        templates = json.load(f)
    for _, template in templates.items():
        if "SRC_IP" in template or "DST_IP" in template:
            template["ip_version"] = "ipv4"
        elif "SRC_IPV6" in template or "DST_IPV6" in template:
            template["ip_version"] = "ipv6"
        elif "IP_TYPE" in template:
            type = template["IP_TYPE"]

            if "ipv4" in type.lower() or "arp" in type.lower():
                template["ip_version"] = "ipv4"
            elif "ipv6" in type.lower():
                template["ip_version"] = "ipv6"
            else:
                template["ip_version"] = "either"
        else:
            template["ip_version"] = "either"

        template["RULE_TEMPLATE"] = {}
        template_keys = [k for k, v in template.items()]
        for k in template_keys:
            if not (k == "ACL_TABLE_NAME" or k == "SRC_DOMAIN" or k == "DST_DOMAIN" or  k == "ip_version" or k == "RULE_TEMPLATE"):
                template["RULE_TEMPLATE"][k] = template[k]
                del template[k]
    
    return templates
# templates = getTemplates()

# with open("out.json", "w") as f:
#     json.dump(templates, f, indent=4)

# for _, template in templates.items():
#     hash = hashlib.sha256((json.dumps(template["RULE_TEMPLATE"], sort_keys=True)).encode(encoding="utf-8", errors="replace")).hexdigest()[:5]
#     print(hash)

def fake_nslookup(domain):
    """Temporary function that returns fake IP addresses for a given domain in nslookup.json

    Args:
        domain (String): domain name to resolve IP addresses for

    Returns:
        list: IP addresses for the given domain, or empty list if the domain isn't found
    """
    with open("nslookup.json") as f:
        ips = json.load(f)
    return ips.get(domain, [])

def updateRules():
    """Iterates through each template, conducts an nslookup, and compares against existing rules.
    This method creates an add patch for any rule that needs to be added or modified, and a remove patch for any extra rule.
    Both rules with old ips as well as old rules without existing templates will be marked for removal.
    Rules that don't start with the prefix will not be touched.

    Returns:
        list: dictionaries for each patch
    """
    patches = []
    templates = getTemplates()
    existing_rules = getExistingRules()
    seen_templates = set()

    # only replaces ips, doesn't update rules if they were changed
    for template_name, template in templates.items():
        if "SRC_DOMAIN" in template:
            src_dst = "SRC"
        elif "DST_DOMAIN" in template:
            src_dst = "DST"
        else:
            src_dst = ""
            continue #################### DOMAIN IS MANDATORY IN YANG FILE ############################
        domain = template[src_dst + "_DOMAIN"][:7]
        #hash = hashlib.sha256((json.dumps(template["RULE_TEMPLATE"], sort_keys=True)).encode(encoding="utf-8", errors="replace")).hexdigest()[:5]
        table = template["ACL_TABLE_NAME"]
            
        rule_name = PREFIX + src_dst + "_" + domain + "_" + template_name + "_"

        matching_rules = {} # Rules that match the template perfectly
        modified_rules = {} # Rules that used to match the template but now don't due to a template update
        nums_used = set()

        if table in existing_rules and src_dst in existing_rules[table] and domain in existing_rules[table][src_dst] and template_name in existing_rules[table][src_dst][domain]:
            for rule in existing_rules[table][src_dst][domain][template_name]:
                if rule["rule"] == template["RULE_TEMPLATE"]:
                    matching_rules[rule["ip"]] = rule
                    nums_used.add(rule["number"])
                else:
                    modified_rules[rule["ip"]] = rule
                    nums_used.add(rule["number"])
        
        #queried_ips = nslookup(template[src_dst + "_DOMAIN"]) # Create mockup of nslookup
        queried_ips = set(fake_nslookup(template[src_dst + "_DOMAIN"]))
        new_ips = set()

        # Only considers queried ips that match the version(s) the template supports
        if template["ip_version"] == "either":
            new_ips = queried_ips
        else:
            for ip in queried_ips:
                address, mask = ip.split("/")
                ipaddress_obj = ipaddress.ip_address(address)

                if ipaddress_obj.version == 4 and template["ip_version"] == "ipv4":
                    new_ips.add(ip)
                elif ipaddress_obj.version == 6 and template["ip_version"] == "ipv6":
                    new_ips.add(ip)

        old_matching_ips = set(matching_rules.keys()).difference(new_ips)
        old_modified_ips = set(modified_rules.keys())
        extra_new_ips = new_ips.difference(set(matching_rules.keys()))

        last_checked_num = 1
        while len(extra_new_ips) > 0:
            new_ip = extra_new_ips.pop()
            if len(old_matching_ips) > 0:
                old_ip = old_matching_ips.pop()
                number = matching_rules[old_ip]["number"]
            elif len(old_modified_ips) > 0:
                old_ip = old_modified_ips.pop()
                number = modified_rules[old_ip]["number"]
            else:
                while(last_checked_num in nums_used):
                    last_checked_num += 1
                number = last_checked_num
                nums_used.add(last_checked_num)
                last_checked_num += 1
            path = table + "|" + rule_name + str(number)
            patches.append(createPatch(path, "add", template["RULE_TEMPLATE"], new_ip, src_dst))
        
        for rules, old_ips in [(matching_rules, old_matching_ips), (modified_rules, old_modified_ips)]:
            while len(old_ips) > 0:
                old_ip = old_ips.pop()
                number = rules[old_ip]["number"]
                path = table + "|" + rule_name + str(number)
                patches.append(createPatch(path, "remove"))

        seen_templates.add(tuple([table, src_dst, domain, template_name]))

    # Checks all existing rules and confirms that there is a template for that rule
    for table, src_dsts in existing_rules.items():
        for src_dst, domains in src_dsts.items():
            for domain, template_names in domains.items():
                for template_name, rule_list in template_names.items():
                    if tuple([table, src_dst, domain, template_name]) not in seen_templates:
                        for rule in rule_list:
                            path = table + "|" + PREFIX + src_dst + "_" + domain + "_" + template_name + "_" + str(rule["number"])
                            patches.append(createPatch(path, "remove"))

    return patches

patches = updateRules() # generate all the patches to update the ACL_RULES

with open("patches.json", "w") as f: # dump the patches in a json
    json.dump(patches, f, indent=4)

# subprocess.run("sudo config apply-patch patches.json", shell=True) # apply the patches using GCU

# subprocess.run("sudo rm patches.json", shell=True) # delete the json