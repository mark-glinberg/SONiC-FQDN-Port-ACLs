# Open and read original sonic-acl.yang file
directory_path = "/usr/local/yang-models/"
with open(directory_path + "sonic-acl.yang", "r") as f:
    acl_yang = f.readlines()

fqdn_yang = []

# Define variables for deleting extraneous containers we don't need
extra_container = False
count = 0

# Iterate through every line of sonic-acl.yang
for i in range(len(acl_yang)):
    # Get the new line
    new_line = acl_yang[i]

    # Add sonic-acl import before all other import statements
    if "import ietf-inet-types" in new_line:
        acl_import = ["\timport sonic-acl {\n",
                      "\t\tprefix acl;\n",
                      "\t}\n",
                      "\n"]
        fqdn_yang.extend(acl_import)

    # Modify revision date of sonic-acl import and also add the revision date for the current file
    if "revision " in new_line:
        revision_date = new_line[len("\trevision "):-3]
        for i in range(len(fqdn_yang)):
            if fqdn_yang[i] == "\timport sonic-acl {\n":
                fqdn_yang.insert(i+2, "\t\trevision-date " + revision_date + ";\n")
                break    
        new_line = new_line.replace(revision_date, "2024-06-28")            

    # # Add typedefs for the fqdn-ipv4 and fqdn-ipv6 prefixes
    # if "container sonic-acl {" in new_line:
    #     type_def = ['\ttypedef fqdn-ipv4-prefix {\n',
    #                 '\t\ttype string {\n',
    #                 "\t\t\tpattern '((([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}'\n",
    #                 "\t\t\t\t+ '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'\n",
    #                 "\t\t\t\t+ '/(([0-9])|([1-2][0-9])|(3[0-2])))'\n",
    #                 "\t\t\t\t+ '|\\(\\(FQDN_IP\\)\\)';\n",
    #                 '\t\t}\n',
    #                 '\t}\n',
    #                 '\n',
    #                 '\ttypedef fqdn-ipv6-prefix {\n',
    #                 '\t\ttype string {\n',
    #                 "\t\t\tpattern '(((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}'\n",
    #                 "\t\t\t\t+ '((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|'\n",
    #                 "\t\t\t\t+ '(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}'\n",
    #                 "\t\t\t\t+ '(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))'\n",
    #                 "\t\t\t\t+ '(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8]))))'\n",
    #                 "\t\t\t\t+ '|\\(\\(FQDN_IP\\)\\)';\n",
    #                 "\t\t\tpattern '((([^:]+:){6}(([^:]+:[^:]+)|(.*\\..*)))|'\n",
    #                 "\t\t\t\t+ '((([^:]+:)*[^:]+)?::(([^:]+:)*[^:]+)?)'\n",
    #                 "\t\t\t\t+ '(/.+))'\n",
    #                 "\t\t\t\t+ '|\\(\\(FQDN_IP\\)\\)';\n",
    #                 '\t\t}\n',
    #                 '\t}\n',
    #                 '\n']
    #     fqdn_yang.extend(type_def)

    # Modify RULE_NAME leaf to TEMPLATE_NAME leaf and add domain choice
    if "leaf RULE_NAME" in new_line:
        new_leafs = ['\t\t\t\tleaf TEMPLATE_NAME {\n',
                     '\t\t\t\t\ttype string {\n',
                     '\t\t\t\t\t\tpattern "([^_]){1,255}";\n'
                     '\t\t\t\t\t}\n',
                     '\t\t\t\t}\n',
                     '\n',
                     '\t\t\t\tchoice src_dst_domain {\n',
                     '\t\t\t\t\tmandatory true;\n',
                     '\n',
                     '\t\t\t\t\tcase source_domain {\n',
                     '\t\t\t\t\t\tleaf SRC_DOMAIN {\n',
                     '\t\t\t\t\t\t\ttype inet:domain-name;\n',
                     '\t\t\t\t\t\t}\n',
                     '\t\t\t\t\t}\n',
                     '\n',
                     '\t\t\t\t\tcase dest_domain {\n',
                     '\t\t\t\t\t\tleaf DST_DOMAIN {\n',
                     '\t\t\t\t\t\t\ttype inet:domain-name;\n',
                     '\t\t\t\t\t\t}\n',
                     '\t\t\t\t\t}\n',
                     '\t\t\t\t}\n']
        fqdn_yang.extend(new_leafs)
        extra_container = True

    # Modify src_dst_address to account for src_dst_domain
    if "choice src_dst_address" in new_line:
        choice_address = ['\t\t\t\tchoice src_dst_address {\n',
                          '\t\t\t\t\tcase src_ip4_prefix {\n',
                          '\t\t\t\t\t\twhen "not(SRC_DOMAIN) and (not(IP_TYPE) or boolean(IP_TYPE[.=\'ANY\' or .=\'IP\' or .=\'IPV4\' or .=\'IPv4ANY\' or .=\'IPV4ANY\' or .=\'ARP\']))";\n',
                          '\t\t\t\t\t\tleaf SRC_IP {\n',
                          '\t\t\t\t\t\t\ttype inet:ipv4-prefix;\n'
                          '\t\t\t\t\t\t}\n',
                          '\t\t\t\t\t}\n',
                          '\n',
                          '\t\t\t\t\tcase src_ip6_prefix {\n',
                          '\t\t\t\t\t\twhen "not(SRC_DOMAIN) and (not(IP_TYPE) or boolean(IP_TYPE[.=\'ANY\' or .=\'IP\' or .=\'IPV6\' or .=\'IPv6ANY\' or .=\'IPV6ANY\']))";\n',
                          '\t\t\t\t\t\tleaf SRC_IPV6 {\n',
                          '\t\t\t\t\t\t\ttype inet:ipv6-prefix;\n'
                          '\t\t\t\t\t\t}\n',
                          '\t\t\t\t\t}\n',
                          '\n',
                          '\t\t\t\t\tcase dst_ip4_prefix {\n',
                          '\t\t\t\t\t\twhen "not(DST_DOMAIN) and (not(IP_TYPE) or boolean(IP_TYPE[.=\'ANY\' or .=\'IP\' or .=\'IPV4\' or .=\'IPv4ANY\' or .=\'IPV4ANY\' or .=\'ARP\']))";\n',
                          '\t\t\t\t\t\tleaf DST_IP {\n',
                          '\t\t\t\t\t\t\ttype inet:ipv4-prefix;\n'
                          '\t\t\t\t\t\t}\n',
                          '\t\t\t\t\t}\n',
                          '\n',
                          '\t\t\t\t\tcase dst_ip6_prefix {\n',
                          '\t\t\t\t\t\twhen "not(DST_DOMAIN) and (not(IP_TYPE) or boolean(IP_TYPE[.=\'ANY\' or .=\'IP\' or .=\'IPV6\' or .=\'IPv6ANY\' or .=\'IPV6ANY\']))";\n',
                          '\t\t\t\t\t\tleaf DST_IPV6 {\n',
                          '\t\t\t\t\t\t\ttype inet:ipv6-prefix;\n'
                          '\t\t\t\t\t\t}\n',
                          '\t\t\t\t\t}\n',
                          '\t\t\t\t}\n',]
        fqdn_yang.extend(choice_address)
        extra_container = True

    # Change relative paths to absolute paths
    if "../.." in new_line:
        new_line = new_line.replace("../..", "/sonic-acl")
        new_line = new_line.replace("/", "/acl:")
        
    # Replace all necessary text in every line after addding in all new text
    new_line = new_line.replace("sonic-acl", "sonic-fqdn-acl-template")
    
    new_line = new_line.replace(":sonic-fqdn-acl-template", ":sonic-acl")

    new_line = new_line.replace("prefix acl", "prefix fqdn")

    new_line = new_line.replace("ACL_RULE", "FQDN_ACL_RULE_TEMPLATE")
        
    new_line = new_line.replace("ACL_TABLE_NAME RULE_NAME", "TEMPLATE_NAME")

    # new_line = new_line.replace("inet:ipv4-prefix", "fqdn-ipv4-prefix")

    # new_line = new_line.replace("inet:ipv6-prefix", "fqdn-ipv6-prefix")

    # Change any mention remaining of "ACL" to "FQDN"
    new_line = new_line.replace("ACL ", "FQDN ")

    # Flag an unnecessary container
    if "container" in new_line and ("sonic-fqdn-acl-template" not in new_line and "FQDN_ACL_RULE_TEMPLATE" not in new_line):
        extra_container = True

    # Skip lines within an extraneous container
    if extra_container:
        comment = False
        for c in new_line:
            if not comment and c == "*":
                comment = True
            elif c == "*":
                comment = False
            elif not comment and c == "{":
                count += 1
            elif not comment and c == "}":
                count -= 1
        
        # If all open curly braces are closed, then the extraneous container ended, skip one last line
        if count == 0:
            extra_container = False
        continue        

    # Add the newly changed line to the new yang file text
    fqdn_yang.append(new_line)

# Write to the new sonic-fqdn-acl-template.yang file
with open(directory_path + "sonic-fqdn-acl-template.yang", "w") as f:
    f.writelines(fqdn_yang)
