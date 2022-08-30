#!/usr/bin/python3
# coding=utf-8
import json

data = []
f = open("./Benign_list_big_final.csv")
# f = open("./test.csv")
line = f.readline()
while line:
    line = line[7:-1]
    if line[0] == '/':
        line = line[1:]
    if line[-1] == '/':
        line = line[:-1]
    line = line.replace("?", "/?")
    tmp = line.split('/')
    item = {}
    item["domainname"] = tmp[0]
    dn = tmp[0].split('.')
    item["prefix_cnum"] = len(dn)
    dn.reverse()
    tmp[0] = '/'.join(dn)
    item["prefix"] = tmp[0] + '/'
    item["fullname_cnum"] = len(dn) + len(tmp) - 1
    item["fullname"] = '/'.join(tmp)
    data.append(item)
    line = f.readline()
f.close()
with open("output_parsed.json", "w") as f:
    json.dump(data, f, indent=4)
