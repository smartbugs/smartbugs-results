import os
import json
import datetime
import matplotlib.pyplot as plt
from matplotlib.dates import (YEARLY, DateFormatter,
                              rrulewrapper, RRuleLocator, drange)



tool_categories = {}

with open('vulnerabilities_mapping.csv') as fd:
    header = fd.readline().strip().split(',')
    line = fd.readline()
    while line:
        tool = header[0]
        v = line.strip().split(',')
        index = -1
        if 'TRUE' in v:
            index = v.index('TRUE')
        elif 'MAYBE' in v:
            index = v.index('MAYBE')
        if index > -1 and header[index] != 'Ignore':
            if tool not in tool_categories:
                tool_categories[tool] = []
            tool_categories[tool].append(header[index])
        line = fd.readline()


analisis = {}
with open('results.json') as fd:
    analisis = json.load(fd)

balances = {}
with open('balances.json') as fd:
    balances = json.load(fd)

duplicates = {}
with open('duplicates.json') as fd:
    duplicates = json.load(fd)

lines = {}
with open('nb_lines.csv') as fd:
    line = fd.readline()
    while line:
        try:
            (address, nb_lines) =  line.strip().split(',')
            lines[address] = int(nb_lines)
        except Exception as e:
            pass
        line = fd.readline()

data = {}
with open('not_empty.csv') as fd:
    line = fd.readline()
    while line:
        (address, nb_transaction, creation_date, last_transaction, hash, compiler_version, name, balance) = line.strip().split(',')

        last_transaction = last_transaction.replace(' UTC', '')
        last_transaction = datetime.datetime.strptime(last_transaction, '%Y-%m-%d %H:%M:%S')

        creation_date = creation_date.replace(' UTC', '')
        creation_date = datetime.datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')

        nb_transaction = int(nb_transaction)

        data[address] = {
            'nb_transaction': nb_transaction,
            'creation_date': creation_date,
            'last_transaction': last_transaction,
            'compiler_version': compiler_version,
            'name': name,
            'balance': balance
        }
        line = fd.readline()



x = []
known_nb_vulnerabilities_axis = []
x_lines = []
correlation_vulnerabilities_balance_y = []
correlation_vulnerabilities_transaction_y = []
correlation_vulnerabilities_version_y = []
correlation_vulnerabilities_date_y = []
correlation_vulnerabilities_last_transaction_y = []
correlation_vulnerabilities_line_y = []

stat_vulnerable_lines = {}
stat_lines = {}

stat_vulnerabilities_per_contract = {}
stat_known_vulnerabilities_per_contract = {}
stat_dencity_line = {}

count_cat_tool = {}

count_tool_solo = {}
count_tool_backup = {}

for unique in duplicates:
    for address in duplicates[unique]:
        balance = balances[address]

        nb_vulnerabilities = 0
        known_nb_vulnerabilities = 0
        nb_vulnerable_line = 0

        if unique in analisis:
            contract = analisis[unique]
            nb_vulnerabilities = contract['nb_vulnerabilities']
            nb_vulnerable_line = len(contract['lines'])

            cat_detected_by = {}

            for tool_name in contract['tools']:
                tool = contract['tools'][tool_name]
                for cat in tool['categories']:
                    if cat == 'unknown':
                        continue
                    known_nb_vulnerabilities += tool['categories'][cat]
                    if cat not in cat_detected_by:
                        cat_detected_by[cat] = []
                    if tool_name not in cat_detected_by[cat]:
                        if cat not in count_cat_tool:
                            count_cat_tool[cat] = {}
                        if tool_name not in count_cat_tool[cat]:
                            count_cat_tool[cat][tool_name] = 0
                        count_cat_tool[cat][tool_name] += 1
                        cat_detected_by[cat].append(tool_name)

            for cat in cat_detected_by:
                tools = cat_detected_by[cat]
                if len(tools) == 1:
                    tool = tools[0]
                    if tool not in count_tool_solo:
                        count_tool_solo[tool]  = {}
                    if cat not in count_tool_solo[tool]:
                        count_tool_solo[tool][cat] = 0
                    count_tool_solo[tool][cat] += 1
                elif len(tools) > 2:
                    for tool in tools:
                        if tool not in count_tool_backup:
                            count_tool_backup[tool]  = {}
                        if cat not in count_tool_backup[tool]:
                            count_tool_backup[tool][cat] = 0
                        count_tool_backup[tool][cat] += 1

            density = round(nb_vulnerable_line/lines[unique], 4)
            if (nb_vulnerable_line > lines[unique]):
                print(unique, nb_vulnerable_line, lines[unique], contract['lines'])
            
            if density not in stat_dencity_line:
                stat_dencity_line[density] = 0
            stat_dencity_line[density] += 1

        if nb_vulnerabilities not in stat_vulnerabilities_per_contract:
            stat_vulnerabilities_per_contract[nb_vulnerabilities] = 0
        stat_vulnerabilities_per_contract[nb_vulnerabilities] += 1

        if nb_vulnerable_line not in stat_vulnerable_lines:
            stat_vulnerable_lines[nb_vulnerable_line] = 0
        stat_vulnerable_lines[nb_vulnerable_line] += 1

        if known_nb_vulnerabilities not in stat_known_vulnerabilities_per_contract:
            stat_known_vulnerabilities_per_contract[known_nb_vulnerabilities] = 0
        stat_known_vulnerabilities_per_contract[known_nb_vulnerabilities] += 1

        x.append(nb_vulnerabilities)
        known_nb_vulnerabilities_axis.append(known_nb_vulnerabilities)
        correlation_vulnerabilities_balance_y.append(balance)

        correlation_vulnerabilities_transaction_y.append(data[address]['nb_transaction'])
        correlation_vulnerabilities_date_y.append(data[address]['creation_date'])
        correlation_vulnerabilities_last_transaction_y.append(data[address]['last_transaction'])

        version = data[address]['compiler_version']
        version = version[3]
        correlation_vulnerabilities_version_y.append(version)

        correlation_vulnerabilities_line_y.append(lines[unique])
        if lines[unique] not in stat_lines:
            stat_lines[lines[unique]] = 0
        stat_lines[lines[unique]] += 1

        pass

for tool in sorted(count_tool_solo):
    for cat in count_tool_solo[tool]:
        print(tool, cat, 
            count_tool_solo[tool][cat], 
            count_cat_tool[cat][tool], 
            count_tool_solo[tool][cat]/count_cat_tool[cat][tool])
    for cat in count_tool_backup[tool]:
        print(tool, cat, count_tool_backup[tool][cat], count_cat_tool[cat][tool], count_tool_backup[tool][cat]/count_cat_tool[cat][tool])

    normalized_tool_solo = [count_tool_solo[tool][i] / count_cat_tool[i][tool] for i in sorted(count_tool_solo[tool])]

    plt.figure(figsize=(8,6))
    plt.bar(sorted([*count_tool_solo[tool]]), normalized_tool_solo)
    plt.xlabel('Category')
    plt.ylabel('# detection where %s is detecting alone a vulnerability' % tool)
    plt.ylim(0, 1)
    plt.savefig('plots/stat_%s_solo' % (tool), dpi=350)
    plt.close()

    normalized_tool_backup = [count_tool_backup[tool][i]/ count_cat_tool[i][tool] for i in sorted(count_tool_backup[tool])]

    plt.figure(figsize=(8,6))
    plt.bar(sorted([*count_tool_backup[tool]]), normalized_tool_backup)
    plt.xlabel('Category')
    plt.ylabel('# detection where %s is at least backup by 2 other tools' % tool)
    plt.ylim(0, 1)
    plt.savefig('plots/stat_%s_backup' % (tool), dpi=350)
    plt.close()


plt.figure(figsize=(8,6))
plt.plot([*stat_lines], [*stat_lines.values()], 'ro', markersize=1)
plt.plot([*stat_vulnerable_lines], [*stat_vulnerable_lines.values()], 'o', markersize=1)
plt.xlabel('# vulnerable line')
plt.ylabel('# contracts')
plt.yscale('log')
plt.xscale('log')
plt.savefig('plots/stat_vulnerable_lines', dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot([*stat_dencity_line], [*stat_dencity_line.values()], 'o', markersize=1)
plt.xlabel('% vulnerable lines')
plt.ylabel('# contracts')
plt.yscale('log')
plt.savefig('plots/stat_dencity_line', dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot([*stat_vulnerabilities_per_contract], [*stat_vulnerabilities_per_contract.values()], 'o', markersize=1)
plt.xlabel('# vulns')
plt.ylabel('# contracts')
plt.yscale('log')
plt.xscale('log')
plt.savefig('plots/stat_vulnerabilities_per_contract', dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot([*stat_known_vulnerabilities_per_contract], [*stat_known_vulnerabilities_per_contract.values()], 'o', markersize=1)
plt.xlabel('# vulns')
plt.ylabel('# contracts')
plt.yscale('log')
plt.xscale('log')
plt.savefig('plots/stat_known_vulnerabilities_per_contract', dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.xscale('log')
plt.plot(correlation_vulnerabilities_balance_y, x, 'o', markersize=1)
plt.xlabel('Total balance (log)')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_vulnerabilities_balance', dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_transaction_y, x, 'o', markersize=1)
plt.xscale('log')
plt.xlabel('# Transactions (log)')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_vulnerabilities_transaction', dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot_date(correlation_vulnerabilities_date_y, x, 'o', markersize=1)
plt.xlabel('Date')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_vulnerabilities_date', dpi=360)
plt.close()

plt.figure(figsize=(8,6))
plt.plot_date(correlation_vulnerabilities_last_transaction_y, x, 'o', markersize=1)
plt.xlabel('Last Transaction')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_vulnerabilities_last_transaction', dpi=360)
plt.close()

plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_version_y, x, 'o', markersize=1)
plt.xlabel('Version')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_vulnerabilities_version', dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_line_y, x, 'o', markersize=1)
plt.xlabel('# Lines')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_vulnerabilities_line', dpi=350)
plt.close()








plt.figure(figsize=(8,6))
plt.xscale('log')
plt.plot(correlation_vulnerabilities_balance_y, known_nb_vulnerabilities_axis, 'o', markersize=1)
plt.xlabel('Total balance (log)')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_known_vulnerabilities_balance', dpi=350)


plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_transaction_y, x, 'o', markersize=1)
plt.xscale('log')
plt.xlabel('# Transactions (log)')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_known_vulnerabilities_transaction', dpi=350)

plt.figure(figsize=(8,6))
plt.plot_date(correlation_vulnerabilities_date_y, known_nb_vulnerabilities_axis, 'o', markersize=1)
plt.xlabel('Date')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_known_vulnerabilities_date', dpi=360)

plt.figure(figsize=(8,6))
plt.plot_date(correlation_vulnerabilities_last_transaction_y, known_nb_vulnerabilities_axis, 'o', markersize=1)
plt.xlabel('Last Transaction')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_known_vulnerabilities_last_transaction', dpi=360)

plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_version_y, known_nb_vulnerabilities_axis, 'o', markersize=1)
plt.xlabel('Version')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_known_vulnerabilities_version', dpi=350)

plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_line_y, known_nb_vulnerabilities_axis, 'o', markersize=1)
plt.xlabel('# Lines')
plt.ylabel('# vulns')
plt.savefig('plots/correlation_known_vulnerabilities_line', dpi=350)
