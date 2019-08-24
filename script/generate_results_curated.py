import os
import json
import sys
import operator
import re
from datetime import timedelta

tools = ['mythril','slither','osiris','oyente','smartcheck','manticore','maian','securify', 'honeybadger']

output_name = 'curated'

vulnerability_stat = {
}
tool_stat = {}
duration_stat = {}
total_duration = 0
count = {}
output = {}
contract_vulnerabilities = {}

oracle = {}

precisions = {}
contract_precisions = {}
count_vulnerabilities = {}

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

with open(os.path.join(ROOT, 'metadata/vulnerabilities.json')) as fd:
    data = json.load(fd)
    for file in data:
        oracle[file['name'].replace('.sol', '')] = file

nb_tagged_vulnerabilities = 0
for contract in oracle:
    for vuln in oracle[contract]['vulnerabilities']:
        if 'denial_of_service' == vuln['category']:
            vuln['category'] = 'denial_service'
        elif 'unchecked_low_level_calls' == vuln['category']:
            vuln['category'] = 'unchecked_low_calls'
        elif 'other' == vuln['category']:
            vuln['category'] = 'Other'
        if vuln['category'] not in count_vulnerabilities:
            count_vulnerabilities[vuln['category']] = 0
        count_vulnerabilities[vuln['category']] += 1
        nb_tagged_vulnerabilities += 1

vulnerability_mapping = {}
with open(os.path.join(ROOT, 'metadata/vulnerabilities_mapping.csv')) as fd:
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

for category in categories:
    precisions[category] = {}

def add_vul(contract, tool, vulnerability, lines):
    original_vulnerability = vulnerability
    vulnerability = vulnerability.strip().lower().title().replace('_', ' ').replace('.', '').replace('Solidity ', '').replace('Potentially ', '')
    vulnerability = re.sub(r' At Instruction .*', '', vulnerability)

    category = 'unknown'
    if original_vulnerability in vulnerability_mapping:
        category = vulnerability_mapping[original_vulnerability]
    else:
        print(original_vulnerability)
    if category == 'Ignore' or category == 'unknown':
        return
    
    if tool not in precisions[category]:
        precisions[category][tool] = []
    
    if tool not in contract_precisions:
        contract_precisions[tool] = []

    if category not in vulnerability_stat:
        vulnerability_stat[category] = 0
    if tool not in tool_stat:
        tool_stat[tool] = {}
    if category not in tool_stat[tool]:
        tool_stat[tool][category] = 0
        #print("%s\t%s" % (tool, vulnerability_original))

    expected = oracle[contract]
    for vuln in expected['vulnerabilities']:
        if lines is not None:
            for line in lines:
                if line in vuln['lines'] and category == vuln['category']:
                    vuln = {
                        'contract': contract,
                        'category': vuln['category'],
                        'lines': vuln['lines']
                    }
                    if vuln not in precisions[category][tool]:
                        precisions[category][tool].append(vuln)
                    if contract not in contract_precisions[tool]:
                        contract_precisions[tool].append(contract)
                    break

    if contract not in contract_vulnerabilities:
        contract_vulnerabilities[contract] = []

    if category not in contract_vulnerabilities[contract]:
        contract_vulnerabilities[contract].append(category)
    
    tool_stat[tool][category] += 1
    if category not in output[contract]['tools'][tool]['categories']:
        output[contract]['tools'][tool]['categories'][category] = 0
        vulnerability_stat[category] += 1
    output[contract]['tools'][tool]['categories'][category] += 1

    if original_vulnerability not in output[contract]['tools'][tool]['vulnerabilities']:
        output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] = 0
    output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] += 1

for tool in tools:
    path_tool = os.path.abspath(os.path.join(ROOT, 'results', tool))
    path_tool_result = os.path.join(path_tool, output_name)

    if not os.path.exists(path_tool_result):
        continue
    for contract in os.listdir(path_tool_result):
        path_contract = os.path.join(path_tool_result, contract)
        path_result = os.path.join(path_contract, 'result.json')
        
        if not os.path.isdir(path_contract):
            continue
        if not os.path.exists(path_result):
            print("Error with %s" % (path_result))
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
                    'lines': [],
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
                        add_vul(contract, tool, vulnerability, [result['lineno']])
            elif tool == 'oyente' or tool == 'osiris' or tool == 'honeybadger':
                for analysis in data['analysis']:
                    if analysis['errors'] is not None:
                        for result in analysis['errors']:
                            vulnerability = result['message'].strip()
                            add_vul(contract, tool, vulnerability, [result['line']])
            elif tool == 'manticore':
                for analysis in data['analysis']:
                    for result in analysis:
                        vulnerability = result['name'].strip()
                        add_vul(contract, tool, vulnerability, [result['line']])
            elif tool == 'maian':
                for vulnerability in data['analysis']:
                    if data['analysis'][vulnerability]:
                        add_vul(contract, tool, vulnerability, None)
            elif tool == 'securify':
                for f in data['analysis']:
                    analysis = data['analysis'][f]['results']
                    for vulnerability in analysis:
                        for line in analysis[vulnerability]['violations']:
                            add_vul(contract, tool, vulnerability, [line + 1])
            elif tool == 'slither':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['check'].strip()
                    line = None
                    if 'source_mapping' in result['elements'][0] and len(result['elements'][0]['source_mapping']['lines']) > 0:
                        line = result['elements'][0]['source_mapping']['lines']
                    add_vul(contract, tool, vulnerability, line)
            elif tool == 'smartcheck':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['name'].strip()
                    add_vul(contract, tool, vulnerability, [result['line']])
            elif tool == 'solhint':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['type'].strip()
                    add_vul(contract, tool, vulnerability, [int(result['line'])])

with open(os.path.join(ROOT, 'metadata/results_curated.json'), 'w') as fd:
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


print("\n# Accuracy\n")


total_precision = []
index_vulnerability = 1
line = '|  Category           |'
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
    total_detection_tool = 0
    total_category_precision = []
    for tool in sorted(tools):
        found = 0
        if tool not in total_tools:
            total_tools[tool] = 0
        if tool in precisions[category]:
            found = len(precisions[category][tool])
            for vuln in precisions[category][tool]:
                if vuln not in total_precision:
                    total_precision.append(vuln)
                if vuln not in total_category_precision:
                    total_category_precision.append(vuln)
        total_tools[tool] += found
        expected = count_vulnerabilities[category]

        total_identified = 0
        if category in tool_stat[tool]:
            total_identified = tool_stat[tool][category]
        total_detection_tool += total_identified
        line += "  {:>5} {:3}% |".format("{:}/{:}".format(found, expected), round(found*100/expected))
    line += "  {:2}/{:2} {:3}% |".format(len(total_category_precision), count_vulnerabilities[category], round(len(total_category_precision)*100/count_vulnerabilities[category]))
    print(line)
    index_vulnerability += 1
line = "| {:19} |".format('Total')
for tool in sorted(tools):
    found = total_tools[tool]
    expected = nb_tagged_vulnerabilities
    line += " {:2}/{:2} {:3}% |".format(found, expected, round(found*100/expected))
line += " {:2}/{:2} {:3}% |".format(len(total_precision), nb_tagged_vulnerabilities, round(len(total_precision)*100/nb_tagged_vulnerabilities))
print(line)

print("\n# Nb Detected Vulnerabilities\n")

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
    total_detection_tool = 0
    for tool in sorted(tools):
        if tool not in total_tools:
            total_tools[tool] = 0

        total_identified = 0
        if category in tool_stat[tool]:
            total_identified = tool_stat[tool][category]
        total_detection_tool += total_identified
        total_tools[tool] += total_identified
        line += " {:11} |".format(total_identified)
    line += " {:11} |".format(total_detection_tool)
    print(line)
    index_vulnerability += 1
line = "| {:19} |".format('Total')
total = 0
for tool in sorted(tools):
    total += total_tools[tool]
    line += " {:11} |".format(total_tools[tool])
line += " {:11} |".format(total)
print(line)


print("\n# Combine tools ")

tool_ability = {}
for category in categories:
    for tool in precisions[category]:
        if tool not in tool_ability:
            tool_ability[tool] = []
        vulns = precisions[category][tool]
        for vuln in vulns:
            tool_ability[tool].append(vuln)

line = '| {:11} |'.format('')
for tool_a in sorted(tools):
    line += ' {:^11} |'.format(tool_a.title())
print(line)
line = '| {:-<11} |'.format('-')
for tool_a in sorted(tools):
    line += ' {:-<11} |'.format('-')
print(line)

for tool_a in sorted(tools):
    line = '| {:11} |'.format(tool_a.title())

    ability_a = tool_ability[tool_a]
    stop_number = True
    for tool_b in sorted(tools):
        if tool_a == tool_b or stop_number:
            line += ' {:11} |'.format('')
            if tool_a == tool_b:
                stop_number = False
            continue
        ability_b = [*tool_ability[tool_b]]
        for vuln in ability_a:
            if vuln not in ability_b:
                ability_b.append(vuln)
        line += ' {:7} {:2}% |'.format("%d/%d" %(len(ability_b), nb_tagged_vulnerabilities),round(len(ability_b)*100/nb_tagged_vulnerabilities))
    print(line)

print("\n# Vulnerability Stat\n")

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

# for contract in output:
#     print("## {:1} {:2}\n".format(index_contract, contract))
#     print("|  #  | Tools      | Vulnerabilities |")
#     print("| --- | ---------- | --------------- |")
#     index_tool = 1
#     for tool in sorted(output[contract]['tools']):
#         line = "| {:3} | {:10} | {} |".format(index_tool, tool.title(), ", ".join(sorted(output[contract]['tools'][tool]['vulnerabilities'])))
#         print(line)
#         index_tool += 1
#     print('')
#     index_contract += 1
