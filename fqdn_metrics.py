import fqdn
import json
import subprocess
import time
import psutil
import csv

def createTemplates(number):
    template_patches = []
    first_patch = {"op": "add",
                   "path": "/FQDN_ACL_RULE_TEMPLATE",
                   "value": {"TEMPLATE1": {"ACL_TABLE_NAME": "DATAACL",
                                           "SRC_DOMAIN": "microsoft.com",
                                           "PRIORITY": "1",
                                           "PACKET_ACTION": "FORWARD"}}}
    template_patches.append(first_patch)
    for i in range(2, number + 1):
        path = "/FQDN_ACL_RULE_TEMPLATE/TEMPLATE" + str(i)
        patch = {"op": "add",
                 "path": path,
                 "value": {"ACL_TABLE_NAME": "DATAACL",
                           "SRC_DOMAIN": "microsoft.com",
                           "PRIORITY": str(i),
                           "PACKET_ACTION": "FORWARD"}}
        template_patches.append(patch)

    with open("template_patches.json", "w") as f:
        json.dump(template_patches, f, indent=4)

    subprocess.run("sudo config apply-patch template_patches.json", shell=True)

def modifyMutableTemplates():
    with open("template_patches.json", "r") as f:
        template_patches = json.load(f)
    
    template_patches[0]["value"]["TEMPLATE1"]["PACKET_ACTION"] = "DROP"
    for i in range(1, len(template_patches)):
        template_patches[i]["value"]["PACKET_ACTION"] = "DROP"

    with open("template_patches.json", "w") as f:
        json.dump(template_patches, f, indent=4)
        
    subprocess.run("sudo config apply-patch template_patches.json", shell=True)

def modifyImmutableTemplates():
    with open("template_patches.json", "r") as f:
        template_patches = json.load(f)
    
    template_patches[0]["value"]["TEMPLATE1"]["DST_DOMAIN"] = "microsoft.com"
    del template_patches[0]["value"]["TEMPLATE1"]["SRC_DOMAIN"]
    for i in range(1, len(template_patches)):
        template_patches[i]["value"]["DST_DOMAIN"] = "microsoft.com"
        del template_patches[i]["value"]["SRC_DOMAIN"]

    with open("template_patches.json", "w") as f:
        json.dump(template_patches, f, indent=4)
        
    subprocess.run("sudo config apply-patch template_patches.json", shell=True)
            
def deleteTemplates():
    delete_templates = [{"op": "remove",
                        "path": "/FQDN_ACL_RULE_TEMPLATE"}]
    
    with open("template_patches.json", "w") as f:
        json.dump(delete_templates, f, indent=4)
        
    subprocess.run("sudo config apply-patch template_patches.json", shell=True)

    subprocess.run("sudo rm template_patches.json", shell=True)

def createFakeIPs(amount):
    fake_ips = "\n"
    for i in range(amount):
        fake_ips += str(i) + "." + str(i) + "." + str(i) + "." + str(i) + "\t\tmicrosoft.com"
        if i < amount - 1:
            fake_ips += "\n"
    with open("/etc/hosts", "a") as f:
        f.write(fake_ips)

def deleteFakeIPs():
    with open("/etc/hosts", "r") as f:
        lines = [line.rstrip() for line in f]
    
    kept_lines = []
    for line in lines:
        if "microsoft.com" not in line:
            kept_lines.append(line)
        else:
            ip, host = line.split()
            octet_1, octet_2, octet_3, octet_4 = ip.split(".")
            if not (octet_1 == octet_2 == octet_3 == octet_4):
                kept_lines.append(line)
    
    kept_ips = "\n".join(kept_lines)
    with open("/etc/hosts", "w") as f:
        f.writelines(kept_ips)

def modifyFakeIps(amount):
    deleteFakeIPs()
    
    fake_ips = "\n"
    for i in range(amount):
        fake_ips += str(255-i) + "." + str(255-i) + "." + str(255-i) + "." + str(255-i) + "\t\tmicrosoft.com"
        if i < amount - 1:
            fake_ips += "\n"
    with open("/etc/hosts", "a") as f:
        f.write(fake_ips)

def getMetrics(num_templates, num_IPs):
    times = [str(num_templates), str(num_IPs)]
    cpu_percents = [str(num_templates), str(num_IPs)]
    script_times = []
    script_cpus = []

    createFakeIPs(num_IPs)

    createTemplates(num_templates)
    cpu_1 = psutil.cpu_percent(interval=None)
    time_1 = time.time()
    script_time, script_cpu = fqdn.main()
    time_2 = time.time()
    cpu_2 = psutil.cpu_percent(interval=None)

    script_times.append(str(script_time))
    script_cpus.append(str(script_cpu))
    cpu_percents.append(str(cpu_2))
    times.append(str(time_2 - time_1))

    modifyFakeIps(num_IPs)
    cpu_1 = psutil.cpu_percent(interval=None)
    time_1 = time.time()
    script_time, script_cpu = fqdn.main()
    time_2 = time.time()
    cpu_2 = psutil.cpu_percent(interval=None)

    script_times.append(str(script_time))
    script_cpus.append(str(script_cpu))
    cpu_percents.append(str(cpu_2))
    times.append(str(time_2 - time_1))

    modifyMutableTemplates()
    cpu_1 = psutil.cpu_percent(interval=None)
    time_1 = time.time()
    script_time, script_cpu = fqdn.main()
    time_2 = time.time()
    cpu_2 = psutil.cpu_percent(interval=None)

    script_times.append(str(script_time))
    script_cpus.append(str(script_cpu))
    cpu_percents.append(str(cpu_2))
    times.append(str(time_2 - time_1))

    modifyImmutableTemplates()
    cpu_1 = psutil.cpu_percent(interval=None)
    time_1 = time.time()
    script_time, script_cpu = fqdn.main()
    time_2 = time.time()
    cpu_2 = psutil.cpu_percent(interval=None)

    script_times.append(str(script_time))
    script_cpus.append(str(script_cpu))
    cpu_percents.append(str(cpu_2))
    times.append(str(time_2 - time_1))

    deleteTemplates()
    cpu_1 = psutil.cpu_percent(interval=None)
    time_1 = time.time()
    script_time, script_cpu = fqdn.main()
    time_2 = time.time()
    cpu_2 = psutil.cpu_percent(interval=None)

    script_times.append(str(script_time))
    script_cpus.append(str(script_cpu))
    cpu_percents.append(str(cpu_2))
    times.append(str(time_2 - time_1))

    deleteFakeIPs()

    times.extend(script_times)
    cpu_percents.extend(script_cpus)

    return times, cpu_percents

def printMetrics(output):
    max_lengths = [0 for i in range(len(output[0]))]
    for row in output:
        for i in range(len(row)):
            if max_lengths[i] < len(row[i]):
                max_lengths[i] = len(row[i])

    format_string = "|"
    for max_length in max_lengths:
        format_string += " {:<" + str(max_length) + "} |"
    
    for row in output:
        print(format_string.format(*row))

def main():
    template_amounts = [5, 10, 15, 20]
    ip_amounts = [1, 4, 7]

    time_output = [["Time", "(s)",
                    "", "", "Total", "", "",
                    "", "", "Script", "", "",],
                   ["Number of Templates",
                    "Number of IP Addresses",
                    "Create Rules",
                    "Modify IPs",
                    "Modify Rules",
                    "Replace Rules",
                    "Delete Rules",
                    "Create Rules",
                    "Modify IPs",
                    "Modify Rules",
                    "Replace Rules",
                    "Delete Rules"]]
    cpu_output = [["CPU Usage", "(%)",
                    "", "", "Total", "", "",
                    "", "", "Script", "", "",],
                  ["Number of Templates",
                   "Number of IP Addresses",
                   "Create Rules",
                   "Modify IPs",
                   "Modify Rules",
                   "Replace Rules",
                   "Delete Rules",
                   "Create Rules",
                   "Modify IPs",
                   "Modify Rules",
                   "Replace Rules",
                   "Delete Rules"]]

    for template_amount in template_amounts:
        for ip_amount in ip_amounts:
            times, cpu_percents = getMetrics(template_amount, ip_amount)
            time_output.append(times)
            cpu_output.append(cpu_percents)
    
    printMetrics(time_output)
    print()
    printMetrics(cpu_output)

    full_output = []
    full_output.extend(time_output)
    full_output.append([])
    full_output.extend(cpu_output)

    with open("metrics.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(full_output)

main()