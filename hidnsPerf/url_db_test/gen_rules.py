#!/usr/bin/python3
# coding=utf-8
import json

with open("output_parsed.json", 'r') as f:
	data = json.load(f)

# generate 500 rules
uniq_prefix = {}
rules = []
size = 500
with open("prefix_500.json", 'w') as f:
	n = 0
	for item in data:
		pf = item["prefix"]
		if pf not in uniq_prefix:
			uniq_prefix[pf] = 1
			rules.append(pf)
			n += 1
		if n == size:
			break

	for item in data:
		if item["prefix_cnum"] == 2 and item["fullname_cnum"] > 2:
			if item["fullname"].split('/')[2].isalpha():
				pf = item["prefix"] + item["fullname"].split('/')[2] + '/'
				if pf not in uniq_prefix:
					uniq_prefix[pf] = 1
					rules.append(pf)
					n += 1
		if n == size:
			break
	
	json.dump(rules, f, indent=4)


		
		