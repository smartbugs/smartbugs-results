import os
import json
import sys
import operator
import re
from datetime import timedelta

tools = ['mythril','slither','oyente','osiris','smartcheck','manticore','maian','securify', 'honeybadger']

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

output_name = 'icse20'

vulnerability_stat = {
}
tool_stat = {}
tool_category_stat = {}
duration_stat = {}
total_duration = 0
count = {}
output = {}
contract_vulnerabilities = {}

vulnerability_mapping = {}

with open(os.path.join(ROOT, 'metadata', 'vulnerabilities_mapping.csv')) as fd:
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

vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

def add_vul(contract, tool, vulnerability, line):
    original_vulnerability = vulnerability
    vulnerability = vulnerability.strip().lower().title().replace('_', ' ').replace('.', '').replace('Solidity ', '').replace('Potentially ', '')
    vulnerability = re.sub(r' At Instruction .*', '', vulnerability)

    category = 'unknown'
    if original_vulnerability in vulnerability_mapping:
        category = vulnerability_mapping[original_vulnerability]
    if category == 'unknown' or category == 'Ignore':
        return
    if vulnerability not in vulnerability_stat:
        vulnerability_stat[vulnerability] = 0
    if tool not in tool_stat:
        tool_stat[tool] = {}
    if vulnerability not in tool_stat[tool]:
        tool_stat[tool][vulnerability] = 0
        vulnerability_fd.write("%s,%s\n" % (tool, original_vulnerability))
    
    if contract not in contract_vulnerabilities:
        contract_vulnerabilities[contract] = set()

    if vulnerability not in contract_vulnerabilities[contract]:
        vulnerability_stat[vulnerability] += 1
        tool_stat[tool][vulnerability] += 1
        contract_vulnerabilities[contract].add(vulnerability)
    
    output[contract]['nb_vulnerabilities'] += 1
    if line is not None and line > 0:
        output[contract]['lines'].add(line)
    if original_vulnerability not in output[contract]['tools'][tool]['vulnerabilities']:
        output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] = 0
    output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] += 1
    

    if category not in output[contract]['tools'][tool]['categories']:
        output[contract]['tools'][tool]['categories'][category] = 0
    output[contract]['tools'][tool]['categories'][category] += 1

    if tool not in tool_category_stat:
        tool_category_stat[tool] = {}
    if category not in tool_category_stat[tool]:
        tool_category_stat[tool][category] = set()
    vuln = contract
    tool_category_stat[tool][category].add(vuln)


index = 0
nb_contract = 0
with open(os.path.join(ROOT, 'metadata', 'unique_contracts.csv')) as ufd:
    line = ufd.readline()
    while line:
        contract = line.split(',')[0]
        index += 1
        for tool in tools:
            path_result = os.path.join('results', tool, output_name, contract, 'result.json')
            if not os.path.exists(path_result):
                continue
            with open(path_result, 'r', encoding='utf-8') as fd:
                data = None
                try:
                    data = json.load(fd)
                except Exception as a:
                    continue
                if tool not in duration_stat:
                    duration_stat[tool] = 0
                if tool not in count:
                    count[tool] = 0
                count[tool] += 1
                duration_stat[tool] += data['duration']
                total_duration += data['duration']

                if contract not in output:
                    output[contract] = {
                        'tools': {},
                        'lines': set(),
                        'nb_vulnerabilities': 0
                    }
                output[contract]['tools'][tool] = {
                    'vulnerabilities': {},
                    'categories': {}
                }
                if data['analysis'] is None:
                    continue
                if tool == 'mythril':
                    analysis = data['analysis']
                    if analysis['issues'] is not None:
                        for result in analysis['issues']:
                            vulnerability = result['title'].strip()
                            add_vul(contract, tool, vulnerability, result['lineno'])
                elif tool == 'oyente' or tool == 'osiris' or tool == 'honeybadger':
                    for analysis in data['analysis']:
                        if analysis['errors'] is not None:
                            for result in analysis['errors']:
                                vulnerability = result['message'].strip()
                                add_vul(contract, tool, vulnerability, result['line'])
                elif tool == 'manticore':
                    for analysis in data['analysis']:
                        for result in analysis:
                            vulnerability = result['name'].strip()
                            add_vul(contract, tool, vulnerability, result['line'])
                elif tool == 'maian':
                    for vulnerability in data['analysis']:
                        if data['analysis'][vulnerability]:
                            add_vul(contract, tool, vulnerability, None)
                elif tool == 'securify':
                    for f in data['analysis']:
                        analysis = data['analysis'][f]['results']
                        for vulnerability in analysis:
                            for line in analysis[vulnerability]['violations']:
                                add_vul(contract, tool, vulnerability, line + 1)
                elif tool == 'slither':
                    analysis = data['analysis']
                    for result in analysis:
                        vulnerability = result['check'].strip()
                        line = None
                        if 'source_mapping' in result['elements'][0] and len(result['elements'][0]['source_mapping']['lines']) > 0:
                            line = result['elements'][0]['source_mapping']['lines'][0] 
                        add_vul(contract, tool, vulnerability, line)
                elif tool == 'smartcheck':
                    analysis = data['analysis']
                    for result in analysis:
                        vulnerability = result['name'].strip()
                        add_vul(contract, tool, vulnerability, result['line'])
                elif tool == 'solhint':
                    analysis = data['analysis']
                    for result in analysis:
                        vulnerability = result['type'].strip()
                        add_vul(contract, tool, vulnerability, int(result['line']))
        line = ufd.readline()

for contract in output:
    output[contract]['lines'] = list(output[contract]['lines'])

with open(os.path.join(ROOT, 'metadata', 'results_wild.json'), 'w') as fd:
    json.dump(output, fd)
#### Generate table ####
print("# Execution Time Stat\n")

index_duration = 1
print("|  #  | Tool       | Avg. Execution Time | Total Execution Time |")
print("| --- | ---------- | ------------------- | -------------------- |")
for tool in sorted(duration_stat):
    value = str(timedelta(seconds=round(duration_stat[tool]/count[tool])))
    line = "| {:3} | {:10} | {:10} | {:10} |".format(index_duration, tool.title(), value, str(timedelta(seconds=round(duration_stat[tool]))))
    index_duration += 1
    print(line)

print("\nTotal: %s" % timedelta(seconds=(round(total_duration))))


print("\n# Detection\n")

line = '| Category            |'
for tool in sorted(tools):
    line += ' {:^11} |'.format(tool.title())
line += ' {:^11} |'.format('Total')
print(line)

line = "| ------------------- |"
for tool in tools:
    line += ' {:-<11} |'.format('-')
line += ' {:-<11} |'.format('')
print(line)

total_tools = {}
for category in categories:
    line = "| {:19} |".format(category.title().replace('_', ' ')) 
    total_detection_tool = set()
    for tool in sorted(tools):
        if tool not in total_tools:
            total_tools[tool] = set()

        total_identified = 0
        if tool in tool_category_stat and category in tool_category_stat[tool]:
            total_identified = len(tool_category_stat[tool][category])
            for vuln in tool_category_stat[tool][category]:
                total_detection_tool.add(vuln)
                total_tools[tool].add(vuln)
        line += " {:11} |".format("%d %.2f%%" % (total_identified, total_identified * 100 / index))
    line += " {:11} |".format("%d %.2f%%" % (len(total_detection_tool), len(total_detection_tool) * 100 / index))
    print(line)
line = "| {:19} |".format('Total')
total = set()
for tool in sorted(tools):
    for vuln in total_tools[tool]:
        total.add(vuln)
    line += " {:11} |".format("%d %.2f%%" % (len(total_tools[tool]), len(total_tools[tool]) * 100 / index))
line += " {:11} |".format("%d %.2f%%" % (len(total), len(total) * 100 / index))
print(line)


# print("\n# Vulnerability Stat\n")

# index_vulnerability = 1
# print("|  #  | Vulnerability | Count |")
# print("| --- | ------------- | ----- |")
# for (vulnerability, value) in sorted(vulnerability_stat.items(), key=operator.itemgetter(1), reverse=True):
#     line = "| {:3} | {:10} | {:4} |".format(index_vulnerability, vulnerability.title(), value)
#     index_vulnerability += 1
#     print(line)

# print("\n# Tool Vulnerability Stat")

# for tool in sorted(tool_stat):
#     print("\n## %s\n" % (tool.title()))
#     index_vulnerability = 1
#     print("|  #  | Vulnerability | Count |")
#     print("| --- | ------------- | ----- |")
#     for (vulnerability, value) in sorted(tool_stat[tool].items(), key=operator.itemgetter(1), reverse=True):
#         line = "| {:3} | {:10} | {:4} |".format(index_vulnerability, vulnerability.title(), value)
#         index_vulnerability += 1
#         print(line)

# print("\n# Contract Vulnerabilities\n")

# index_contract = 1

# with open(os.path.join(ROOT, 'metadata', 'unique_contracts.csv')) as fd:
#     line = fd.readline()
#     while line:
#         contract = line.split(',')[0]
#         if contract not in output:
#             line = fd.readline()
#             continue
#         nb_transaction = line.split(',')[1].strip()

#         print("## {:1} {:2} (# Tranaction {:3}) \n".format(index_contract, contract, nb_transaction))
#         print("|  #  | Tools      | Vulnerabilities |")
#         print("| --- | ---------- | --------------- |")
#         index_tool = 1
#         for tool in sorted(output[contract]['tools']):
#             line = "| {:3} | {:10} | {} |".format(index_tool, tool.title(), ", ".join(sorted(output[contract]['tools'][tool]['vulnerabilities'])))
#             print(line)
#             index_tool += 1
#         print('')
#         index_contract += 1
#         line = fd.readline()


