import fqdn
import asyncio
import unittest
import socket
import ipaddress
import json
import subprocess
import pathlib

def writeToFile(file, content):
    with open(file, "w") as f:
        json.dump(content, f, indent=4)
        
def readFromFile(file):
    with open(file, "r") as f:
        output = json.load(f)
    return output

def deleteFile(file):
    path = pathlib.Path(file)
    path.unlink()

class TestPatches(unittest.TestCase):
    def setUp(self) -> None:  
        self.path = "TEST"
        self.template = {"PACKET_ACTION": "FORWARD",
                         "PRIORITY": "1"}
        self.src = "SRC"
        self.dst = "DST"
        self.ipv4 = "1.1.1.1/32"
        self.ipv6 = "2607:f8b0:4002:c10::8a/128"
        self.remove = "remove"
        self.add = "add"

    def test_Remove(self):
        out = asyncio.run(fqdn.createPatch(self.path, self.remove))
        expected = {"op": self.remove,
                    "path": ("/ACL_RULE/" + self.path)}
        self.assertEqual(out, expected)
        
    def test_Remove_With_Extra_Inputs(self):
        out = asyncio.run(fqdn.createPatch(self.path, self.remove, self.template, self.ipv4, self.src))
        expected = {"op": self.remove,
                    "path": ("/ACL_RULE/" + self.path)}
        self.assertEqual(out, expected)
        
    def test_Add_src_ipv4(self):
        out = asyncio.run(fqdn.createPatch(self.path, self.add, self.template, self.ipv4, self.src))
        expected = {"op": self.add,
                    "path": ("/ACL_RULE/" + self.path),
                    "value": {"PACKET_ACTION": "FORWARD",
                              "PRIORITY": "1",
                              "SRC_IP": self.ipv4}}
        self.assertEqual(out, expected)
        
    def test_Add_dst_ipv4(self):
        out = asyncio.run(fqdn.createPatch(self.path, self.add, self.template, self.ipv4, self.dst))
        expected = {"op": self.add,
                    "path": ("/ACL_RULE/" + self.path),
                    "value": {"PACKET_ACTION": "FORWARD",
                              "PRIORITY": "1",
                              "DST_IP": self.ipv4}}
        self.assertEqual(out, expected)

    def test_Add_src_ipv6(self):
        out = asyncio.run(fqdn.createPatch(self.path, self.add, self.template, self.ipv6, self.src))
        expected = {"op": self.add,
                    "path": ("/ACL_RULE/" + self.path),
                    "value": {"PACKET_ACTION": "FORWARD",
                              "PRIORITY": "1",
                              "SRC_IPV6": self.ipv6}}
        self.assertEqual(out, expected)
        
    def test_Add_dst_ipv6(self):
        out = asyncio.run(fqdn.createPatch(self.path, self.add, self.template, self.ipv6, self.dst))
        expected = {"op": self.add,
                    "path": ("/ACL_RULE/" + self.path),
                    "value": {"PACKET_ACTION": "FORWARD",
                              "PRIORITY": "1",
                              "DST_IPV6": self.ipv6}}
        self.assertEqual(out, expected)

class TestIPs(unittest.TestCase):
    def setUp(self) -> None:  
        self.domains = ["microsoft.com", "amazon.com"]

    def testCorrectIPs(self):
        out = asyncio.run(fqdn.get_ip_addresses(self.domains))

        expected = {}
        for domain in self.domains:
            nslookup_cmd = "nslookup " + domain
            nslookup_out = subprocess.run(nslookup_cmd, capture_output=True, text=True).stdout
            if "Addresses:" in nslookup_out:
                expected_ips = nslookup_out.split("Addresses:")[1].split()
            else:
                expected_ips = nslookup_out.split("Address:")[2].split()

            expected[domain] = {"ipv4": set(), "ipv6": set()}
            for ip in expected_ips:
                ipaddress_obj = ipaddress.ip_address(ip)

                if ipaddress_obj.version == 4:
                    expected[domain]["ipv4"].add(ip + "/32")
                elif ipaddress_obj.version == 6:
                    expected[domain]["ipv6"].add(ip + "/128")
        self.assertEqual(expected, out)

class TestRules(unittest.TestCase):
    def tearDown(self):
        deleteFile("rules.json")

    def test_Regular_Rule(self):
        regular_rule = {"TABLE|FQDN_RUL_this_is_a_rule": {
                                    "PACKET_ACTION": "FORWARD",
                                    "PRIORITY": "1",
                                    "SRC_IP": "1.1.1.1/32"}}
        writeToFile("rules.json", regular_rule)
        rules = asyncio.run(fqdn.getExistingRules())
        self.assertEqual({}, rules)
        self.assertFalse(rules)

    def test_ipv4_rules(self):
        ipv4_rules = {"TABLE|FQDN_RULE_SRC_microso_testplate_1": {
                            "PACKET_ACTION": "FORWARD",
                            "PRIORITY": "1",
                            "SRC_IP": "1.1.1.1/32"},
                        "TABLE|FQDN_RULE_DST_microso_testplate_1": {
                            "PACKET_ACTION": "FORWARD",
                            "PRIORITY": "1",
                            "DST_IP": "2.2.2.2/32"},
                        "TABLE|FQDN_RULE_SRC_microso_testplate_2": {
                            "PACKET_ACTION": "FORWARD",
                            "PRIORITY": "1",
                            "SRC_IP": "3.3.3.3/32",
                            "DST_IP": "4.4.4.4/32"},
                        "TABLE|FQDN_RULE_DST_microso_testplate_2": {
                            "PACKET_ACTION": "FORWARD",
                            "PRIORITY": "1",
                            "SRC_IP": "5.5.5.5/32",
                            "DST_IP": "6.6.6.6/32"}}
        writeToFile("rules.json", ipv4_rules)
        
        rules = asyncio.run(fqdn.getExistingRules())
        expected = {"TABLE": {"SRC": {"microso": {"testplate": [{"number": 1,
                                                                 "ip": "1.1.1.1/32",
                                                                 "rule": {"PACKET_ACTION": "FORWARD",
                                                                          "PRIORITY": "1"}},
                                                                {"number": 2,
                                                                 "ip": "3.3.3.3/32",
                                                                 "rule": {"PACKET_ACTION": "FORWARD",
                                                                          "PRIORITY": "1",
                                                                          "DST_IP": "4.4.4.4/32"}}]}},
                              "DST": {"microso": {"testplate": [{"number": 1,
                                                                 "ip": "2.2.2.2/32",
                                                                 "rule": {"PACKET_ACTION": "FORWARD",
                                                                          "PRIORITY": "1"}},
                                                                {"number": 2,
                                                                 "ip": "6.6.6.6/32",
                                                                 "rule": {"PACKET_ACTION": "FORWARD",
                                                                          "PRIORITY": "1",
                                                                          "SRC_IP": "5.5.5.5/32"}}]}}}}
        self.assertEqual(json.dumps(rules), json.dumps(expected))

    def test_ipv6_rules(self):
        ipv6_rules = {"TABLE|FQDN_RULE_SRC_microso_testplate_1": {
                            "PACKET_ACTION": "FORWARD",
                            "PRIORITY": "1",
                            "SRC_IPV6": "FF01::1/128"},
                        "TABLE|FQDN_RULE_DST_microso_testplate_1": {
                            "PACKET_ACTION": "FORWARD",
                            "PRIORITY": "1",
                            "DST_IPV6": "FF01::2/128"},
                        "TABLE|FQDN_RULE_SRC_microso_testplate_2": {
                            "PACKET_ACTION": "FORWARD",
                            "PRIORITY": "1",
                            "SRC_IPV6": "FF01::3/128",
                            "DST_IPV6": "FF01::4/128"},
                        "TABLE|FQDN_RULE_DST_microso_testplate_2": {
                            "PACKET_ACTION": "FORWARD",
                            "PRIORITY": "1",
                            "SRC_IPV6": "FF01::5/128",
                            "DST_IPV6": "FF01::6/128"}}
        writeToFile("rules.json", ipv6_rules)
        
        rules = asyncio.run(fqdn.getExistingRules())
        expected = {"TABLE": {"SRC": {"microso": {"testplate": [{"number": 1,
                                                                 "ip": "FF01::1/128",
                                                                 "rule": {"PACKET_ACTION": "FORWARD",
                                                                          "PRIORITY": "1"}},
                                                                {"number": 2,
                                                                 "ip": "FF01::3/128",
                                                                 "rule": {"PACKET_ACTION": "FORWARD",
                                                                          "PRIORITY": "1",
                                                                          "DST_IPV6": "FF01::4/128"}}]}},
                              "DST": {"microso": {"testplate": [{"number": 1,
                                                                 "ip": "FF01::2/128",
                                                                 "rule": {"PACKET_ACTION": "FORWARD",
                                                                          "PRIORITY": "1"}},
                                                                {"number": 2,
                                                                 "ip": "FF01::6/128",
                                                                 "rule": {"PACKET_ACTION": "FORWARD",
                                                                          "PRIORITY": "1",
                                                                          "SRC_IPV6": "FF01::5/128"}}]}}}}
        self.assertEqual(json.dumps(rules), json.dumps(expected))

    def test_Rule_Sorting(self):
        all_rules = {
            "TABLE_1|RULE_1": {
                "PRIORITY": "100",
                "IP_TYPE": "IPV4",
                "DST_IP": "20.0.0.10/32",
                "PACKET_ACTION": "DROP"
            },
            "TABLE_2|RULE_1": {
                "PRIORITY": "100",
                "IP_TYPE": "IPV4",
                "DST_IP": "20.0.0.10/32",
                "PACKET_ACTION": "DROP"
            },

            "TABLE_0|FQDN_RULE_SRC_microso_TEMPLATE0_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "0.0.0.1/32"
            },
            "TABLE_0|FQDN_RULE_SRC_microso_TEMPLATE0_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "0.0.0.2/32",
                "DST_IP": "0.0.0.2/16"
            },
            "TABLE_0|FQDN_RULE_SRC_microso_TEMPLATE0_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::0003/128"
            },
            "TABLE_0|FQDN_RULE_SRC_microso_TEMPLATE0_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::0004/128",
                "DST_IPV6": "FF01::0004/64"
            },

            "TABLE_0|FQDN_RULE_SRC_microso_TEMPLATE1_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "0.0.1.1/32"
            },
            "TABLE_0|FQDN_RULE_SRC_microso_TEMPLATE1_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "0.0.1.2/32",
                "DST_IP": "0.0.1.2/16"
            },
            "TABLE_0|FQDN_RULE_SRC_microso_TEMPLATE1_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::0013/128"
            },
            "TABLE_0|FQDN_RULE_SRC_microso_TEMPLATE1_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::0014/128",
                "DST_IPV6": "FF01::0014/64"
            },

            "TABLE_0|FQDN_RULE_DST_microso_TEMPLATE0_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "0.1.0.1/32"
            },
            "TABLE_0|FQDN_RULE_DST_microso_TEMPLATE0_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "0.1.0.2/32",
                "SRC_IP": "0.1.0.2/16"
            },
            "TABLE_0|FQDN_RULE_DST_microso_TEMPLATE0_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::0103/128"
            },
            "TABLE_0|FQDN_RULE_DST_microso_TEMPLATE0_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::0104/128",
                "SRC_IPV6": "FF01::0104/64"
            },

            "TABLE_0|FQDN_RULE_DST_microso_TEMPLATE1_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "0.1.1.1/32"
            },
            "TABLE_0|FQDN_RULE_DST_microso_TEMPLATE1_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "0.1.1.2/32",
                "SRC_IP": "0.1.1.2/16"
            },
            "TABLE_0|FQDN_RULE_DST_microso_TEMPLATE1_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::0113/128"
            },
            "TABLE_0|FQDN_RULE_DST_microso_TEMPLATE1_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::0114/128",
                "SRC_IPV6": "FF01::0114/64"
            },

            "TABLE_1|FQDN_RULE_SRC_microso_TEMPLATE0_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "1.0.0.1/32"
            },
            "TABLE_1|FQDN_RULE_SRC_microso_TEMPLATE0_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "1.0.0.2/32",
                "DST_IP": "1.0.0.2/16"
            },
            "TABLE_1|FQDN_RULE_SRC_microso_TEMPLATE0_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::1003/128"
            },
            "TABLE_1|FQDN_RULE_SRC_microso_TEMPLATE0_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::1004/128",
                "DST_IPV6": "FF01::1004/64"
            },

            "TABLE_1|FQDN_RULE_SRC_microso_TEMPLATE1_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "1.0.1.1/32"
            },
            "TABLE_1|FQDN_RULE_SRC_microso_TEMPLATE1_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "1.0.1.2/32",
                "DST_IP": "1.0.1.2/16"
            },
            "TABLE_1|FQDN_RULE_SRC_microso_TEMPLATE1_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::1013/128"
            },
            "TABLE_1|FQDN_RULE_SRC_microso_TEMPLATE1_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::1014/128",
                "DST_IPV6": "FF01::1014/64"
            },

            "TABLE_1|FQDN_RULE_DST_microso_TEMPLATE0_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "1.1.0.1/32"
            },
            "TABLE_1|FQDN_RULE_DST_microso_TEMPLATE0_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "1.1.0.2/32",
                "SRC_IP": "1.1.0.2/16"
            },
            "TABLE_1|FQDN_RULE_DST_microso_TEMPLATE0_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::1103/128"
            },
            "TABLE_1|FQDN_RULE_DST_microso_TEMPLATE0_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::1104/128",
                "SRC_IPV6": "FF01::1104/64"
            },

            "TABLE_1|FQDN_RULE_DST_microso_TEMPLATE1_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "1.1.1.1/32"
            },
            "TABLE_1|FQDN_RULE_DST_microso_TEMPLATE1_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "1.1.1.2/32",
                "SRC_IP": "1.1.1.2/16"
            },
            "TABLE_1|FQDN_RULE_DST_microso_TEMPLATE1_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::1113/128"
            },
            "TABLE_1|FQDN_RULE_DST_microso_TEMPLATE1_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::1114/128",
                "SRC_IPV6": "FF01::1114/64"
            },

            "TABLE_0|FQDN_RULE_SRC_google._TEMPLATE0_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "0.0.0.1/32"
            },
            "TABLE_0|FQDN_RULE_SRC_google._TEMPLATE0_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "0.0.0.2/32",
                "DST_IP": "0.0.0.2/16"
            },
            "TABLE_0|FQDN_RULE_SRC_google._TEMPLATE0_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::0003/128"
            },
            "TABLE_0|FQDN_RULE_SRC_google._TEMPLATE0_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::0004/128",
                "DST_IPV6": "FF01::0004/64"
            },

            "TABLE_0|FQDN_RULE_SRC_google._TEMPLATE1_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "0.0.1.1/32"
            },
            "TABLE_0|FQDN_RULE_SRC_google._TEMPLATE1_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "0.0.1.2/32",
                "DST_IP": "0.0.1.2/16"
            },
            "TABLE_0|FQDN_RULE_SRC_google._TEMPLATE1_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::0013/128"
            },
            "TABLE_0|FQDN_RULE_SRC_google._TEMPLATE1_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::0014/128",
                "DST_IPV6": "FF01::0014/64"
            },

            "TABLE_0|FQDN_RULE_DST_google._TEMPLATE0_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "0.1.0.1/32"
            },
            "TABLE_0|FQDN_RULE_DST_google._TEMPLATE0_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "0.1.0.2/32",
                "SRC_IP": "0.1.0.2/16"
            },
            "TABLE_0|FQDN_RULE_DST_google._TEMPLATE0_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::0103/128"
            },
            "TABLE_0|FQDN_RULE_DST_google._TEMPLATE0_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::0104/128",
                "SRC_IPV6": "FF01::0104/64"
            },

            "TABLE_0|FQDN_RULE_DST_google._TEMPLATE1_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "0.1.1.1/32"
            },
            "TABLE_0|FQDN_RULE_DST_google._TEMPLATE1_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "0.1.1.2/32",
                "SRC_IP": "0.1.1.2/16"
            },
            "TABLE_0|FQDN_RULE_DST_google._TEMPLATE1_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::0113/128"
            },
            "TABLE_0|FQDN_RULE_DST_google._TEMPLATE1_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::0114/128",
                "SRC_IPV6": "FF01::0114/64"
            },

            "TABLE_1|FQDN_RULE_SRC_google._TEMPLATE0_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "1.0.0.1/32"
            },
            "TABLE_1|FQDN_RULE_SRC_google._TEMPLATE0_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "1.0.0.2/32",
                "DST_IP": "1.0.0.2/16"
            },
            "TABLE_1|FQDN_RULE_SRC_google._TEMPLATE0_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::1003/128"
            },
            "TABLE_1|FQDN_RULE_SRC_google._TEMPLATE0_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::1004/128",
                "DST_IPV6": "FF01::1004/64"
            },

            "TABLE_1|FQDN_RULE_SRC_google._TEMPLATE1_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "1.0.1.1/32"
            },
            "TABLE_1|FQDN_RULE_SRC_google._TEMPLATE1_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "1.0.1.2/32",
                "DST_IP": "1.0.1.2/16"
            },
            "TABLE_1|FQDN_RULE_SRC_google._TEMPLATE1_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::1013/128"
            },
            "TABLE_1|FQDN_RULE_SRC_google._TEMPLATE1_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "SRC_IPV6": "FF01::1014/128",
                "DST_IPV6": "FF01::1014/64"
            },

            "TABLE_1|FQDN_RULE_DST_google._TEMPLATE0_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "1.1.0.1/32"
            },
            "TABLE_1|FQDN_RULE_DST_google._TEMPLATE0_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "1.1.0.2/32",
                "SRC_IP": "1.1.0.2/16"
            },
            "TABLE_1|FQDN_RULE_DST_google._TEMPLATE0_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::1103/128"
            },
            "TABLE_1|FQDN_RULE_DST_google._TEMPLATE0_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::1104/128",
                "SRC_IPV6": "FF01::1104/64"
            },

            "TABLE_1|FQDN_RULE_DST_google._TEMPLATE1_1": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "1.1.1.1/32"
            },
            "TABLE_1|FQDN_RULE_DST_google._TEMPLATE1_2": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IP": "1.1.1.2/32",
                "SRC_IP": "1.1.1.2/16"
            },
            "TABLE_1|FQDN_RULE_DST_google._TEMPLATE1_3": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::1113/128"
            },
            "TABLE_1|FQDN_RULE_DST_google._TEMPLATE1_4": {
                "PRIORITY": "1",
                "PACKET_ACTION": "FORWARD",
                "DST_IPV6": "FF01::1114/128",
                "SRC_IPV6": "FF01::1114/64"
            }
        }
        writeToFile("rules.json", all_rules)

        rules = asyncio.run(fqdn.getExistingRules())
        expected = {"TABLE_0": {"SRC": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                   "ip": "0.0.0.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "0.0.0.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IP": "0.0.0.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::0003/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::0004/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IPV6": "FF01::0004/64"}}],
                                                    "TEMPLATE1": [{"number": 1,
                                                                   "ip": "0.0.1.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "0.0.1.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IP": "0.0.1.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::0013/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::0014/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IPV6": "FF01::0014/64"}}]},
                                        "google.": {"TEMPLATE0": [{"number": 1,
                                                                   "ip": "0.0.0.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "0.0.0.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IP": "0.0.0.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::0003/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::0004/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IPV6": "FF01::0004/64"}}],
                                                    "TEMPLATE1": [{"number": 1,
                                                                   "ip": "0.0.1.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "0.0.1.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IP": "0.0.1.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::0013/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::0014/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IPV6": "FF01::0014/64"}}]}},
                                "DST": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                   "ip": "0.1.0.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "0.1.0.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IP": "0.1.0.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::0103/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::0104/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IPV6": "FF01::0104/64"}}],
                                                    "TEMPLATE1": [{"number": 1,
                                                                   "ip": "0.1.1.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "0.1.1.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IP": "0.1.1.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::0113/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::0114/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IPV6": "FF01::0114/64"}}]},
                                        "google.": {"TEMPLATE0": [{"number": 1,
                                                                   "ip": "0.1.0.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "0.1.0.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IP": "0.1.0.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::0103/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::0104/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IPV6": "FF01::0104/64"}}],
                                                    "TEMPLATE1": [{"number": 1,
                                                                   "ip": "0.1.1.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "0.1.1.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IP": "0.1.1.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::0113/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::0114/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IPV6": "FF01::0114/64"}}]}}},
                    "TABLE_1": {"SRC": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                   "ip": "1.0.0.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "1.0.0.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IP": "1.0.0.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::1003/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::1004/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IPV6": "FF01::1004/64"}}],
                                                    "TEMPLATE1": [{"number": 1,
                                                                   "ip": "1.0.1.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "1.0.1.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IP": "1.0.1.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::1013/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::1014/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IPV6": "FF01::1014/64"}}]},
                                        "google.": {"TEMPLATE0": [{"number": 1,
                                                                   "ip": "1.0.0.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "1.0.0.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IP": "1.0.0.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::1003/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::1004/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IPV6": "FF01::1004/64"}}],
                                                    "TEMPLATE1": [{"number": 1,
                                                                   "ip": "1.0.1.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "1.0.1.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IP": "1.0.1.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::1013/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::1014/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "DST_IPV6": "FF01::1014/64"}}]}},
                                "DST": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                   "ip": "1.1.0.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "1.1.0.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IP": "1.1.0.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::1103/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::1104/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IPV6": "FF01::1104/64"}}],
                                                    "TEMPLATE1": [{"number": 1,
                                                                   "ip": "1.1.1.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "1.1.1.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IP": "1.1.1.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::1113/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::1114/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IPV6": "FF01::1114/64"}}]},
                                        "google.": {"TEMPLATE0": [{"number": 1,
                                                                   "ip": "1.1.0.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "1.1.0.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IP": "1.1.0.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::1103/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::1104/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IPV6": "FF01::1104/64"}}],
                                                    "TEMPLATE1": [{"number": 1,
                                                                   "ip": "1.1.1.1/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 2,
                                                                   "ip": "1.1.1.2/32",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IP": "1.1.1.2/16"}},
                                                                  {"number": 3,
                                                                   "ip": "FF01::1113/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD"}},
                                                                  {"number": 4,
                                                                   "ip": "FF01::1114/128",
                                                                   "rule": {"PRIORITY": "1",
                                                                            "PACKET_ACTION": "FORWARD",
                                                                            "SRC_IPV6": "FF01::1114/64"}}]}}}}
        self.assertEqual(json.dumps(rules), json.dumps(expected))
        
class TestTemplates(unittest.TestCase):
    def tearDown(self):
        deleteFile("templates.json")

    def test_Domains(self):
        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "SRC_DOMAIN": "microsoft.com"},
                     "TEMPLATE1": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "DST_DOMAIN": "google.com"},
                     "TEMPLATE2": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "DST_DOMAIN": "microsoft.com"},
                     "TEMPLATE2": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "DST_DOMAIN": "amazon.com"}}
        writeToFile("templates.json", templates)

        templates, seen_templates, domains = asyncio.run(fqdn.getTemplates())
        expected = set(["microsoft.com", "google.com", "amazon.com"])
        self.assertEqual(expected, domains)

    def test_SRC_DST(self):
        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "SRC_DOMAIN": "microsoft.com"},
                     "TEMPLATE1": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "DST_IP": "1.1.1.1/32"},
                     "TEMPLATE2": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "DST_IPV6": "FF01::1111/32"},
                     "TEMPLATE3": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "DST_DOMAIN": "microsoft.com"},
                     "TEMPLATE4": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "DST_DOMAIN": "microsoft.com",
                                   "SRC_IP": "1.1.1.1/32"},
                     "TEMPLATE5": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE",
                                   "DST_DOMAIN": "microsoft.com",
                                   "SRC_IPV6": "FF01::1111/32"}}
        writeToFile("templates.json", templates)

        templates, seen_templates, domains = asyncio.run(fqdn.getTemplates())
        for template_name, template in templates.items():
            number = int(template_name[len("TEMPLATE"):])
            if number < 3:
                self.assertEqual(template["src_dst"], "SRC")
            else:
                self.assertEqual(template["src_dst"], "DST")
        
    def test_Template_Restructuring(self):
        template = {"TEMPLATE": {"PRIORITY": "1",
                                 "PACKET_ACTION": "FORWARD",
                                 "ACL_TABLE_NAME": "TABLE",
                                 "SRC_DOMAIN": "microsoft.com",
                                 "DST_DOMAIN": "azure.com",
                                 "MIRROR_INGRESS_ACTION": "something",
                                 "IP_TYPE": "ANY",
                                 "SRC_IP": "2.2.2.2/32",
                                 "DST_IP": "1.1.1.1/32",
                                 "SRC_IPV6": "FF01:2222/128",
                                 "DST_IPV6": "FF01:1111/128",
                                 "IN_PORTS": "80",
                                 "OUT_PORTS": "443",
                                 "L4_SRC_PORT": 13,
                                 "L4_SRC_PORT_RANGE": "20-25",
                                 "L4_DST_PORT": 39,
                                 "L4_DST_PORT_RANGE": "60-75",
                                 "ETHER_TYPE": "0x0aaaa",
                                 "IP_PROTOCOL": 2,
                                 "TCP_FLAGS": "flag",
                                 "DSCP": 100,
                                 "TC": 200,
                                 "ICMP_TYPE": 150,
                                 "ICMP_CODE": 160,
                                 "ICMPV6_TYPE": 170,
                                 "ICMPV6_CODE": 180,
                                 "INNER_ETHER_TYPE": "pattern",
                                 "INNER_IP_PROTOCOL": 142,
                                 "INNER_L4_SRC_PORT": 16,
                                 "INNER_L4_DST_PORT": 17,
                                 "VLAN_ID": 4094,
                                 "PCP": "77/7",
                                 "DEI": "1",
                                 "BTH_OPCODE": "0x99/0x99",
                                 "AETH_SYNDROME": "0x99/0x99"}}
        writeToFile("templates.json", template)

        templates, seen_templates, domains = asyncio.run(fqdn.getTemplates())
        expected = {"PRIORITY": "1",
                    "PACKET_ACTION": "FORWARD",
                    "MIRROR_INGRESS_ACTION": "something",
                    "IP_TYPE": "ANY",
                    "SRC_IP": "2.2.2.2/32",
                    "DST_IP": "1.1.1.1/32",
                    "SRC_IPV6": "FF01:2222/128",
                    "DST_IPV6": "FF01:1111/128",
                    "IN_PORTS": "80",
                    "OUT_PORTS": "443",
                    "L4_SRC_PORT": 13,
                    "L4_SRC_PORT_RANGE": "20-25",
                    "L4_DST_PORT": 39,
                    "L4_DST_PORT_RANGE": "60-75",
                    "ETHER_TYPE": "0x0aaaa",
                    "IP_PROTOCOL": 2,
                    "TCP_FLAGS": "flag",
                    "DSCP": 100,
                    "TC": 200,
                    "ICMP_TYPE": 150,
                    "ICMP_CODE": 160,
                    "ICMPV6_TYPE": 170,
                    "ICMPV6_CODE": 180,
                    "INNER_ETHER_TYPE": "pattern",
                    "INNER_IP_PROTOCOL": 142,
                    "INNER_L4_SRC_PORT": 16,
                    "INNER_L4_DST_PORT": 17,
                    "VLAN_ID": 4094,
                    "PCP": "77/7",
                    "DEI": "1",
                    "BTH_OPCODE": "0x99/0x99",
                    "AETH_SYNDROME": "0x99/0x99"}
        self.assertEqual(expected, templates["TEMPLATE"]["RULE_TEMPLATE"])

    def test_seen_templates(self):
        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE0",
                                   "SRC_DOMAIN": "microsoft.com"},
                     "TEMPLATE1": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE1",
                                   "SRC_DOMAIN": "microsoft.com"},
                     "TEMPLATE2": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE0",
                                   "DST_DOMAIN": "microsoft.com"},
                     "TEMPLATE3": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE1",
                                   "DST_DOMAIN": "microsoft.com"},
                     "TEMPLATE4": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE0",
                                   "SRC_DOMAIN": "amazon.com"},
                     "TEMPLATE5": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE1",
                                   "SRC_DOMAIN": "amazon.com"},
                     "TEMPLATE6": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE0",
                                   "DST_DOMAIN": "amazon.com"},
                     "TEMPLATE7": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "ACL_TABLE_NAME": "TABLE1",
                                   "DST_DOMAIN": "amazon.com"}}
        writeToFile("templates.json", templates)

        templates, seen_templates, domains = asyncio.run(fqdn.getTemplates())
        
        expected = set([("TABLE0", "SRC", "microso", "TEMPLATE0"),
                        ("TABLE1", "SRC", "microso", "TEMPLATE1"),
                        ("TABLE0", "DST", "microso", "TEMPLATE2"),
                        ("TABLE1", "DST", "microso", "TEMPLATE3"),
                        ("TABLE0", "SRC", "amazon.", "TEMPLATE4"),
                        ("TABLE1", "SRC", "amazon.", "TEMPLATE5"),
                        ("TABLE0", "DST", "amazon.", "TEMPLATE6"),
                        ("TABLE1", "DST", "amazon.", "TEMPLATE7")])
        
        self.assertEqual(seen_templates, expected)

class TestDeleteRules(unittest.TestCase):
    def test_template_name(self):
        seenTemplates = set([("TABLE0", "SRC", "microso", "TEMPLATE0")])
        rules = {"TABLE0": {"SRC": {"microso": {"TEMPLATE0": [{"number": 1,
                                                               "ip": "0.0.0.1/32",
                                                               "rule": {"PRIORITY": "1",
                                                                        "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 2,
                                                                 "ip": "0.0.0.2/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IP": "0.0.0.2/16"}},
                                                                {"number": 3,
                                                                 "ip": "FF01::0003/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 4,
                                                                 "ip": "FF01::0004/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IPV6": "FF01::0004/64"}}],
                                                "TEMPLATE1": [{"number": 1,
                                                                 "ip": "0.0.0.1/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 2,
                                                                 "ip": "0.0.0.2/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IP": "0.0.0.2/16"}},
                                                                {"number": 3,
                                                                 "ip": "FF01::0003/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 4,
                                                                 "ip": "FF01::0004/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IPV6": "FF01::0004/64"}}]}}}}
        patches = asyncio.run(fqdn.deleteOldRules(seenTemplates, rules))

        expected = [{"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_SRC_microso_TEMPLATE1_1"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_SRC_microso_TEMPLATE1_2"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_SRC_microso_TEMPLATE1_3"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_SRC_microso_TEMPLATE1_4"}]
        self.assertEqual(json.dumps(patches), json.dumps(expected))
    
    def test_domain_name(self):
        seenTemplates = set([("TABLE0", "SRC", "microso", "TEMPLATE0")])
        rules = {"TABLE0": {"SRC": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                 "ip": "0.0.0.1/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 2,
                                                                 "ip": "0.0.0.2/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IP": "0.0.0.2/16"}},
                                                                {"number": 3,
                                                                 "ip": "FF01::0003/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 4,
                                                                 "ip": "FF01::0004/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IPV6": "FF01::0004/64"}}]},
                                    "google.": {"TEMPLATE0": [{"number": 1,
                                                                 "ip": "0.0.0.1/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 2,
                                                                 "ip": "0.0.0.2/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IP": "0.0.0.2/16"}},
                                                                {"number": 3,
                                                                 "ip": "FF01::0003/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 4,
                                                                 "ip": "FF01::0004/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IPV6": "FF01::0004/64"}}]}}}}
        patches = asyncio.run(fqdn.deleteOldRules(seenTemplates, rules))

        expected = [{"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_SRC_google._TEMPLATE0_1"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_SRC_google._TEMPLATE0_2"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_SRC_google._TEMPLATE0_3"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_SRC_google._TEMPLATE0_4"}]
        self.assertEqual(json.dumps(patches), json.dumps(expected))
        
    def test_src_dst(self):
        seenTemplates = set([("TABLE0", "SRC", "microso", "TEMPLATE0")])
        rules = {"TABLE0": {"SRC": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                 "ip": "0.0.0.1/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 2,
                                                                 "ip": "0.0.0.2/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IP": "0.0.0.2/16"}},
                                                                {"number": 3,
                                                                 "ip": "FF01::0003/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 4,
                                                                 "ip": "FF01::0004/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IPV6": "FF01::0004/64"}}]}},
                            "DST": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                 "ip": "0.0.0.1/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 2,
                                                                 "ip": "0.0.0.2/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IP": "0.0.0.2/16"}},
                                                                {"number": 3,
                                                                 "ip": "FF01::0003/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 4,
                                                                 "ip": "FF01::0004/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IPV6": "FF01::0004/64"}}]}}}}
        patches = asyncio.run(fqdn.deleteOldRules(seenTemplates, rules))

        expected = [{"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_DST_microso_TEMPLATE0_1"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_DST_microso_TEMPLATE0_2"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_DST_microso_TEMPLATE0_3"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE0|FQDN_RULE_DST_microso_TEMPLATE0_4"}]
        self.assertEqual(json.dumps(patches), json.dumps(expected))

        
    def test_table_name(self):
        seenTemplates = set([("TABLE0", "SRC", "microso", "TEMPLATE0")])
        rules = {"TABLE0": {"SRC": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                 "ip": "0.0.0.1/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 2,
                                                                 "ip": "0.0.0.2/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IP": "0.0.0.2/16"}},
                                                                {"number": 3,
                                                                 "ip": "FF01::0003/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 4,
                                                                 "ip": "FF01::0004/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IPV6": "FF01::0004/64"}}]}}},
                 "TABLE1": {"SRC": {"microso": {"TEMPLATE0": [{"number": 1,
                                                                 "ip": "0.0.0.1/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 2,
                                                                 "ip": "0.0.0.2/32",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IP": "0.0.0.2/16"}},
                                                                {"number": 3,
                                                                 "ip": "FF01::0003/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD"}},
                                                                {"number": 4,
                                                                 "ip": "FF01::0004/128",
                                                                 "rule": {"PRIORITY": "1",
                                                                          "PACKET_ACTION": "FORWARD",
                                                                          "DST_IPV6": "FF01::0004/64"}}]}}}}
                                                                          
        patches = asyncio.run(fqdn.deleteOldRules(seenTemplates, rules))

        expected = [{"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_3"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_4"}]
        self.assertEqual(json.dumps(patches), json.dumps(expected))


# MAKE SURE TO CHANGE THE get_ip_addresses FUNCTION TO QUERY THE nslookup.json FILE INSTEAD OF socket #
class TestUpdate(unittest.TestCase):
    def tearDown(self):
        deleteFile("nslookup.json")
        deleteFile("rules.json")
        deleteFile("templates.json")

    def comparePatches(self, expected, actual):
        expected_patches = {}
        expected_patches["ops"] = [0, 0]
        expected_patches["paths"] = set()
        expected_patches["values"] = set()
        for patch in expected:
            if patch["op"] == "add":
                expected_patches["ops"][0] += 1
            else:
                expected_patches["ops"][1] += 1
            expected_patches["paths"].add(patch["path"])
            expected_patches["values"].add(json.dumps(patch.get("value", "")))

        actual_patches = {}
        actual_patches["ops"] = [0, 0]
        actual_patches["paths"] = set()
        actual_patches["values"] = set()
        for patch in actual:
            if patch["op"] == "add":
                actual_patches["ops"][0] += 1
            else:
                actual_patches["ops"][1] += 1
            actual_patches["paths"].add(patch["path"])
            actual_patches["values"].add(json.dumps(patch.get("value", "")))
        
        if expected_patches["paths"] == actual_patches["paths"]:
            if expected_patches["ops"] == actual_patches["ops"]:
                if expected_patches["values"] == actual_patches["values"]:
                    return True
        return False

    def test_new_rules(self):
        new_ips = {"google.com": ["1.1.1.1", "2.2.2.2"],
                   "microsoft.com": ["0.1.2.3", "FF01::0123"]}
        writeToFile("nslookup.json", new_ips)

        rules = {}
        writeToFile("rules.json", rules)

        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE1"},
                     "TEMPLATE1": {"PRIORITY": "2",
                                   "PACKET_ACTION": "FORWARD",
                                   "DST_DOMAIN": "google.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)

        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IPV6": "FF01::0123/128"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IP": "0.1.2.3/32"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1",
                    "value": {"PRIORITY": "2",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IP": "1.1.1.1/32"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_2",
                    "value": {"PRIORITY": "2",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IP": "2.2.2.2/32"}}]
        self.assertTrue(self.comparePatches(patches, expected))

    def test_update_template(self):
        new_ips = {"google.com": ["1.1.1.1", "2.2.2.2"],
                   "microsoft.com": ["0.1.2.3", "FF01::0123"]}
        writeToFile("nslookup.json", new_ips)

        rules = {"TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IPV6": "FF01::0123/128"},
                 "TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IP": "0.1.2.3/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "1.1.1.1/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "2.2.2.2/32"}}
        writeToFile("rules.json", rules)

        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE1"},
                     "TEMPLATE1": {"PRIORITY": "2",
                                   "PACKET_ACTION": "FORWARD",
                                   "DST_DOMAIN": "google.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)

        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1",
                    "value": {"PRIORITY": "2",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IP": "1.1.1.1/32"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_2",
                    "value": {"PRIORITY": "2",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IP": "2.2.2.2/32"}}]
        self.assertTrue(self.comparePatches(patches, expected))
        
    def test_update_ips_same(self):
        new_ips = {"google.com": ["3.3.3.3", "2.2.2.2"],
                   "microsoft.com": ["FF01::1234", "FF01::0123"]}
        writeToFile("nslookup.json", new_ips)

        rules = {"TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IPV6": "FF01::0123/128"},
                 "TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IP": "0.1.2.3/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "1.1.1.1/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "2.2.2.2/32"}}
        writeToFile("rules.json", rules)

        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE1"},
                     "TEMPLATE1": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "DST_DOMAIN": "google.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)

        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IPV6": "FF01::1234/128"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IP": "3.3.3.3/32"}}]
        self.assertTrue(self.comparePatches(patches, expected))
        
    def test_update_ips_more(self):
        new_ips = {"google.com": ["3.3.3.3", "2.2.2.2"],
                   "microsoft.com": ["FF01::1234", "FF01::0123", "2.3.4.5", "3.4.5.6"]}
        writeToFile("nslookup.json", new_ips)

        rules = {"TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IPV6": "FF01::0123/128"},
                 "TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IP": "0.1.2.3/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "1.1.1.1/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "2.2.2.2/32"}}
        writeToFile("rules.json", rules)

        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE1"},
                     "TEMPLATE1": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "DST_DOMAIN": "google.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)

        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IPV6": "FF01::1234/128"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_3",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IP": "2.3.4.5/32"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_4",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IP": "3.4.5.6/32"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IP": "3.3.3.3/32"}}]
        self.assertTrue(self.comparePatches(patches, expected))
        
    def test_update_ips_less(self):
        new_ips = {"google.com": ["3.3.3.3", "2.2.2.2"],
                   "microsoft.com": ["FF01::2345", "2.3.4.5"]}
        writeToFile("nslookup.json", new_ips)

        rules = {"TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IPV6": "FF01::0123/128"},
                 "TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IP": "0.1.2.3/32"},
                 "TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_3": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IP": "2.3.4.5/32"},
                 "TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_4": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IP": "3.4.5.6/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "1.1.1.1/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "2.2.2.2/32"}}
        writeToFile("rules.json", rules)

        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE1"},
                     "TEMPLATE1": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "DST_DOMAIN": "google.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)

        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IPV6": "FF01::2345/128"}},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2"},
                    {"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_4"},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IP": "3.3.3.3/32"}}]
        self.assertTrue(self.comparePatches(patches, expected))
        
    def test_update_ips_and_templates(self):
        new_ips = {"google.com": ["FF01::2222", "2.2.2.2"],
                   "microsoft.com": ["3.4.5.6", "2.3.4.5"]}
        writeToFile("nslookup.json", new_ips)

        rules = {"TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IPV6": "FF01::0123/128"},
                 "TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IP": "0.1.2.3/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "1.1.1.1/32"},
                 "TABLE1|FQDN_RULE_DST_google._TEMPLATE1_2": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "DST_IP": "2.2.2.2/32"}}
        writeToFile("rules.json", rules)

        templates = {"TEMPLATE0": {"PRIORITY": "2",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE1"},
                     "TEMPLATE1": {"PRIORITY": "2",
                                   "PACKET_ACTION": "FORWARD",
                                   "DST_DOMAIN": "google.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)

        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1",
                    "value": {"PRIORITY": "2",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IP": "3.4.5.6/32"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_2",
                    "value": {"PRIORITY": "2",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IP": "2.3.4.5/32"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_1",
                    "value": {"PRIORITY": "2",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IP": "2.2.2.2/32"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_google._TEMPLATE1_2",
                    "value": {"PRIORITY": "2",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IPV6": "FF01::2222/128"}}]
        self.assertTrue(self.comparePatches(patches, expected))
        
    def test_immutable_template_sections(self):
        new_ips = {"google.com": ["FF01::2222", "2.2.2.2"],
                   "microsoft.com": ["FF01::0123"]}
        writeToFile("nslookup.json", new_ips)

        rules = {"TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1": {"PRIORITY": "1",
                                                        "PACKET_ACTION": "FORWARD",
                                                        "SRC_IPV6": "FF01::1234/128"}}
        writeToFile("rules.json", rules)
        
        # TEMPLATE NAME
        templates = {"TEMPLATE1": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)

        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1"},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE1_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IPV6": "FF01::0123/128"}}]
        self.assertTrue(self.comparePatches(patches, expected))

        # DOMAIN
        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "google.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)
        
        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1"},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_google._TEMPLATE0_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IPV6": "FF01::2222/128"}},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_google._TEMPLATE0_2",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IP": "2.2.2.2/32"}}]
        self.assertTrue(self.comparePatches(patches, expected))

        # SRC_DST
        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "DST_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE1"}}
        writeToFile("templates.json", templates)
        
        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1"},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_DST_microso_TEMPLATE0_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "DST_IPV6": "FF01::0123/128"}}]
        self.assertTrue(self.comparePatches(patches, expected))
        
        # TABLE
        templates = {"TEMPLATE0": {"PRIORITY": "1",
                                   "PACKET_ACTION": "FORWARD",
                                   "SRC_DOMAIN": "microsoft.com",
                                   "ACL_TABLE_NAME": "TABLE2"}}
        writeToFile("templates.json", templates)
        
        patches = asyncio.run(fqdn.updateRules())
        expected = [{"op": "remove",
                    "path": "/ACL_RULE/TABLE1|FQDN_RULE_SRC_microso_TEMPLATE0_1"},
                    {"op": "add",
                    "path": "/ACL_RULE/TABLE2|FQDN_RULE_SRC_microso_TEMPLATE0_1",
                    "value": {"PRIORITY": "1",
                              "PACKET_ACTION": "FORWARD",
                              "SRC_IPV6": "FF01::0123/128"}}]
        self.assertTrue(self.comparePatches(patches, expected))
        
    
if __name__ == '__main__':
    unittest.main()