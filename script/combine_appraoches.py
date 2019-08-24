import os
import json

tools = ['mythril','slither','osiris','oyente','smartcheck','manticore','maian','securify', 'honeybadger']


ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

oracle = {}
with open(os.path.join(ROOT, 'dataset/vulnerabilities.json')) as fd:
    data = json.load(fd)
    for file in data:
        oracle[file['name'].replace('.sol', '')] = file

for contract in oracle:
    for vuln in oracle[contract]['vulnerabilities']:
        if 'denial_of_service' == vuln['category']:
            vuln['category'] = 'denial_service'
        elif 'unchecked_low_level_calls' == vuln['category']:
            vuln['category'] = 'unchecked_low_calls'
        elif 'other' == vuln['category']:
            vuln['category'] = 'Other'

vulnerability_mapping = {}
with open(os.path.join(ROOT, 'vulnerabilities_mapping.csv')) as fd:
    header = fd.readline().strip().split(',')
    line = fd.readline()
    while line:
        v = line.strip().split(',')
        index = -1
        if 'TRUE' in v:
            index = v.index('TRUE')
        elif 'MAYBE' in v:
            index = v.index('MAYBE')
        if index > -1:
            vulnerability_mapping[v[1]] = header[index]
        line = fd.readline()
categories = sorted(list(set(vulnerability_mapping.values())))
categories.remove('Ignore')
categories.remove('Other')
categories.append('Other')

results = {}
with open('results_small.json') as fd:
    results = json.load(fd)

for address in results:
    vuln = results[address]

    expected = oracle[address]
    for vuln in expected['vulnerabilities']: