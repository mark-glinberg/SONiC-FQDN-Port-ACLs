import json
import subprocess
import hashlib

def createPatch(path, op, template=None, ip=None):
    """Creates a patch entry for the Generic Config Updater (GCU)

    Args:
        path ("String"): path of the rule to patch (<TABLE_NAME>|<RULE_NAME>)
        op ("String"): "add" or "remove"
        template ("String", optional): template of the rule if op="add". Defaults to None
        ip ("String", optional): ip of the rule if op="add". Defaults to None.

    Returns:
        dict: the patch for that rule to be read by the GCU
    """
    patch = {}
    patch["op"] = op
    patch["path"] = "/ACL_RULE/" + path
    if op == "add":
        rule = template.replace("((FQDN_IP))", ip)

        rule = rule.replace("\"", "")
        rule = rule.replace("\n", " ")

        lines = rule.split(", ")
        value = {}
        for line in lines:
            entry = line.split(": ")
            value[entry[0]] = entry[1]
        patch["value"] = value
    return patch

def getExistingRules():
    """Queries SONiC for all existing ACL_RULES,
    filters out the non-fqdn rules (keeps only auto-generated ones),
    and returns all generated rules in a sorted, nested dictionary

    Returns:
        dict: nested mapping of rules with keys: table -> domain -> hash -> list of rules with matching templates but different ips
    """
    PREFIX = "FQDN_RULE_"
    rules = {}

    sonic_out = subprocess.run("sonic-cfggen -d --var-json ACL_RULE", shell=True, capture_output=True, text=True)
    existing_rules = json.loads(sonic_out.stdout)
    # with open("rules.json") as f: # Need to replace with the above commands
    #     existing_rules = json.load(f)

    for k, v in existing_rules.items():
        table, name = k.split("|")
        if PREFIX == name[:len(PREFIX)]:
            pre, fix, domain, hash, number = name.split("_")

            value = {}
            value["number"] = int(number)

            ip_source_types = ["DST_IP",
                              "DST_IPV6",
                              "SRC_IP",
                              "SRC_IPV6"]
            
            for type in ip_source_types:
                if type in v:
                    value["ip"] = v[type]
                    v[type] = "((FQDN_IP))"
                    break

            value["rule"] = str(v)
            value["rule"] = value["rule"].replace("{", "")
            value["rule"] = value["rule"].replace("}", "")
            value["rule"] = value["rule"].replace("'", "")
            
            if table not in rules:
                rules[table] = {}

            if domain not in rules[table]:
                rules[table][domain] = {}

            if hash not in rules[table][domain]:
                rules[table][domain][hash] = []

            rules[table][domain][hash].append(value)
    
    return rules

def getTemplates():
    """Queries SONiC for all existing templates and returns them as a list

    Returns:
        list: dictionaries of all existing templates
    """
    sonic_out = subprocess.run("sonic-cfggen -d --var-json FQDN_ACL_RULE_TEMPLATE", shell=True, capture_output=True, text=True)
    templates = json.loads(sonic_out.stdout)
    # with open("templates.json") as f: # need to replace with the above commands
    #     templates = json.load(f)
    return templates

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
    PREFIX = "FQDN_RULE_"
    patches = []
    templates = getTemplates()
    existing_rules = getExistingRules()
    seen_templates = set()

    # only replaces ips, doesn't update rules if they were changed
    for _, template in templates.items():
        domain = template["DOMAIN"][:7]
        hash = hashlib.sha256(template["RULE_TEMPLATE"].encode(encoding="utf-8", errors="replace")).hexdigest()[:5]
        rule_name = PREFIX + domain + "_" + hash + "_"
        table = template["ACL_TABLE_NAME"]

        matching_rules = {}
        nums_used = set()

        if table in existing_rules and domain in existing_rules[table] and hash in existing_rules[table][domain]:
            for rule in existing_rules[table][domain][hash]:
                matching_rules[rule["ip"]] = rule
                nums_used.add(rule["number"])
        
        #new_ips = nslookup(template["DOMAIN"]) # Create mockup of nslookup
        new_ips = set(fake_nslookup(template["DOMAIN"]))
        extra_old_ips = set(matching_rules.keys()).difference(new_ips)
        extra_new_ips = new_ips.difference(matching_rules.keys())

        last_checked_num = 1
        while len(extra_new_ips) > 0:
            new_ip = extra_new_ips.pop()
            if len(extra_old_ips) > 0:
                old_ip = extra_old_ips.pop()
                number = matching_rules[old_ip]["number"]
            else:
                while(last_checked_num in nums_used):
                    last_checked_num += 1
                number = last_checked_num
                nums_used.add(last_checked_num)
                last_checked_num += 1
            path = table + "|" + rule_name + "_" + str(number)
            patches.append(createPatch(path, "add", template["RULE_TEMPLATE"], new_ip))
        
        while len(extra_old_ips) > 0:
            old_ip = extra_old_ips.pop()
            number = matching_rules[old_ip]["number"]
            path = table + "|" + rule_name + "_" + str(number)
            patches.append(createPatch(path, "remove"))

        seen_templates.add(tuple([template["ACL_TABLE_NAME"], template["DOMAIN"], hash]))

    # Checks all existing rules and confirms that there is a template for that rule
    for table, domains in existing_rules.items():
        for domain, hashes in domains.items():
            for hash, rule_list in hashes.items():
                if tuple([table, domain, hash]) not in seen_templates:
                    for rule in rule_list:
                        path = table + "|" + PREFIX + domain + "_" + hash + "_" + str(rule["number"])
                        patches.append(createPatch(path, "remove"))

    return patches

patches = updateRules() # geneate all the patches to update the ACL_RULES

with open("patches.json", "w") as f: # dump the patches in a json
    json.dump(patches, f, indent=4)

subprocess.run("sudo config apply-patch patches.json", shell=True) # apply the patches using GCU

subprocess.run("sudo rm patches.json", shell=True) # delete the json