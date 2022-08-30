#!/usr/bin/python3
# coding=utf-8
import json

stat = {}
plen = 0
minplen = 100
maxplen = 0
with open("output_parsed.json", 'r') as f:
	data = json.load(f)

for item in data:
	pf = item["prefix"] 
	plen += item["prefix_cnum"]
	minplen = min(minplen, item["prefix_cnum"])
	maxplen = max(maxplen, item["prefix_cnum"])
	# print(pf)
	if pf in stat:
		stat[pf] += 1
	else:
		stat[pf] = 1
print("there are %d urls but %d different prefixes\nminplen=%d, maxplen=%d, avrplen=%f" % (len(data), len(stat), minplen, maxplen, plen*1.0/len(data)))
