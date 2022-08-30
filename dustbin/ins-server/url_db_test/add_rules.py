#!/usr/bin/python3
# coding=utf-8
import json
import random
from readline import insert_text

rules_num = 100

with open("prefix_500.json", 'r') as f:
	rules = json.load(f)

# generate config files
with open("config.json", 'r') as f:
	cfg = json.load(f)

ins_local = cfg["INS_PATH_LOCAL"]["prefix"]
ins_remote = cfg["INS_PATH_REMOTE"][0]["prefix"]
dns_mod = cfg["DNS_PATH"][0]["prefix"]

i = 0
for rule in rules:
	r = random.randint(1, 3)
	if r == 1:
		ins_local.append(rule)
	elif r == 2:
		ins_remote.append(rule)
	else:
		dns_mod.append(rule)
	
	i += 1
	if i == rules_num:
		break

with open("config_output_%d.json" % rules_num, 'w') as f:
	json.dump(cfg, f, indent=4)