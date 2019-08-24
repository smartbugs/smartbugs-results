import os
import json
import datetime
import matplotlib.pyplot as plt
from matplotlib.dates import (YEARLY, DateFormatter,
                              rrulewrapper, RRuleLocator, drange)
plt.rcParams.update({'text.usetex': True})
plt.style.use('kpmg')

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

price_history = {}
with open(os.path.join(ROOT, 'metadata', 'eth_price.json')) as fd:
    data = json.load(fd)
    for p in data:
        date = datetime.datetime.fromtimestamp(p['timestamp'])
        price_history[date] = p['price']

tool_categories = {}
categories = set()
with open(os.path.join(ROOT, 'metadata', 'vulnerabilities_mapping.csv')) as fd:
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
            categories.add(header[index])
            if tool not in tool_categories:
                tool_categories[tool] = []
            tool_categories[tool].append(header[index])
        line = fd.readline()

categories = sorted(list(categories))
categories.remove('Other')
categories.append('Other')

analisis = {}
with open(os.path.join(ROOT, 'metadata', 'results_wild.json')) as fd:
    analisis = json.load(fd)

balances = {}
with open(os.path.join(ROOT, 'metadata', 'balances.json')) as fd:
    balances = json.load(fd)

duplicates = {}
with open(os.path.join(ROOT, 'metadata', 'duplicates.json')) as fd:
    duplicates = json.load(fd)

lines = {}
with open(os.path.join(ROOT, 'metadata', 'nb_lines.csv')) as fd:
    line = fd.readline()
    while line:
        try:
            (address, nb_lines) =  line.strip().split(',')
            lines[address] = int(nb_lines)
        except Exception as e:
            pass
        line = fd.readline()

data = {}
with open(os.path.join(ROOT, 'metadata', 'unique_contracts.csv')) as fd:
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

creation_dates = {}
category_creation_date = {}
unique_creation_dates = {}

stat_vulnerable_lines = {}
stat_lines = {}

stat_vulnerabilities_per_contract = {}
stat_known_vulnerabilities_per_contract = {}
stat_dencity_line = {}

count_cat_tool = {}
count_cat = {}

count_tool_solo = {}
count_tool_backup = {}
count_backup = {}

for unique in duplicates:
    unique_creation_date = data[unique]['creation_date']
    if unique_creation_date not in unique_creation_dates:
        unique_creation_dates[unique_creation_date] = 0
    unique_creation_dates[unique_creation_date] += 1

    for address in [unique]: #duplicates[unique]:
        balance = balances[address]

        nb_vulnerabilities = 0
        known_nb_vulnerabilities = 0
        nb_vulnerable_line = 0

        creation_date = data[address]['creation_date']
        if creation_date not in creation_dates:
            creation_dates[creation_date] = 0
        creation_dates[creation_date] += 1

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
                    
                    if cat not in category_creation_date:
                        category_creation_date[cat] = {}
                    if creation_date not in category_creation_date[cat]:
                        category_creation_date[cat][creation_date] = set()
                    category_creation_date[cat][creation_date].add(address)

                    known_nb_vulnerabilities += tool['categories'][cat]
                    if cat not in cat_detected_by:
                        cat_detected_by[cat] = set()
                    if tool_name not in cat_detected_by[cat]:
                        if cat not in count_cat_tool:
                            count_cat_tool[cat] = {}
                        if cat not in count_cat:
                            count_cat[cat] = set()
                        if tool_name not in count_cat_tool[cat]:
                            count_cat_tool[cat][tool_name] = 0
                        count_cat_tool[cat][tool_name] += 1
                        count_cat[cat].add(address)
                        cat_detected_by[cat].add(tool_name)

            for cat in cat_detected_by:
                count = len(cat_detected_by[cat])
                if count > 4:
                    count = 4
                if cat not in count_backup:
                    count_backup[cat] = {} 
                if count not in count_backup[cat]:
                    count_backup[cat][count] = 0 
                count_backup[cat][count] += 1
                for tool in cat_detected_by[cat]:
                    if tool not in count_tool_backup:
                        count_tool_backup[tool]  = {}
                    if cat not in count_tool_backup[tool]:
                        count_tool_backup[tool][cat] = {}
                    if count not in count_tool_backup[tool][cat]:
                        count_tool_backup[tool][cat][count] = 0
                    count_tool_backup[tool][cat][count] += 1
                    

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
print('xticklabels={' + ','.join(categories) + '},')

for tool in sorted(count_tool_backup):
    normalized_tool_backup = {
        1: [],
        2: [],
        3: [],
        4: []
    }
    for category in categories:
        if category in count_tool_backup[tool]:
            for count in normalized_tool_backup:
                total = 0
                if count in count_tool_backup[tool][category]:
                    total = count_tool_backup[tool][category][count]
                normalized_tool_backup[count].append(total*100/count_cat_tool[category][tool])
        else:
            for count in normalized_tool_backup:
                normalized_tool_backup[count].append(0)

    # plt.figure(figsize=(8,6))
    # plt.bar(categories, normalized_tool_backup)
    # plt.xlabel('Categories')
    # plt.ylabel('# detection where %s is at least backup by 2 other tools' % tool)
    # plt.ylim(0, 1)
    # plt.savefig(os.path.join(ROOT, 'plots/stat_%s_backup' % (tool), dpi=350)
    

    line = '\\nextgroupplot[ylabel = %s]\n' % (tool.title())
    colors = {
        1: "bblue",
        2: "rred",
        3: "ggreen",
        4: "ppurple"
    }
    for count in normalized_tool_backup:
        line += '\n\\addplot [style={%s,fill=%s,mark=none}] coordinates{' % (colors[count], colors[count])
        for i in range(len(categories)):
            line += '(%d,%.2f)' % (i, normalized_tool_backup[count][i])
        line += '};'
    print(line+'\n')

normalized_tool_backup = {
    1: [],
    2: [],
    3: [],
    4: []
}
for category in categories:
    if category in count_backup:
        for count in normalized_tool_backup:
            total = 0
            if count in count_backup[category]:
                total = count_backup[category][count]
            normalized_tool_backup[count].append(total*100/len(count_cat[category]))


line = '\\nextgroupplot[ylabel = %s]\n' % ('Total')
colors = {
    1: "bblue",
    2: "rred",
    3: "ggreen",
    4: "ppurple"
}
for count in normalized_tool_backup:
    line += '\n\\addplot [style={%s,fill=%s,mark=none}] coordinates{' % (colors[count], colors[count])
    for i in range(len(categories)):
        line += '(%d,%.2f)' % (i, normalized_tool_backup[count][i])
    line += '};'
print(line+'\n')

plt.figure(figsize=(8,6))
plt.plot([*stat_lines], [*stat_lines.values()], 'ro', markersize=1)
plt.plot([*stat_vulnerable_lines], [*stat_vulnerable_lines.values()], 'o', markersize=1)
plt.xlabel('\# vulnerable line')
plt.ylabel('\# contracts')
plt.yscale('log')
plt.xscale('log')
plt.savefig(os.path.join(ROOT, 'plots/stat_vulnerable_lines'), dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot([*stat_dencity_line], [*stat_dencity_line.values()], 'o', markersize=1)
plt.xlabel('\% vulnerable lines')
plt.ylabel('\# contracts')
plt.yscale('log')
plt.savefig(os.path.join(ROOT, 'plots/stat_dencity_line'), dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot([*stat_vulnerabilities_per_contract], [*stat_vulnerabilities_per_contract.values()], 'o', markersize=1)
plt.xlabel('\# vulns')
plt.ylabel('\# contracts')
plt.yscale('log')
plt.xscale('log')
plt.savefig(os.path.join(ROOT, 'plots/stat_vulnerabilities_per_contract'), dpi=350)
plt.close()

plt.figure(figsize=(8,4))
plt.plot([*stat_known_vulnerabilities_per_contract], [*stat_known_vulnerabilities_per_contract.values()], 'o', markersize=1)
plt.xlabel('\# Vulnerabilities')
plt.ylabel('\# contracts')
plt.yscale('log')
plt.xscale('log')
plt.savefig(os.path.join(ROOT, 'plots/stat_known_vulnerabilities_per_contract'), dpi=350)
plt.close()

plt.figure(figsize=(8,3))
plt.xscale('log')
plt.plot(correlation_vulnerabilities_balance_y, x, 'o', markersize=1)
plt.xlabel('Total balance (log)')
plt.ylabel('\# Vulnerabilities')
plt.savefig(os.path.join(ROOT, 'plots/correlation_vulnerabilities_balance.png'), dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_transaction_y, x, 'o', markersize=1)
plt.xscale('log')
plt.xlabel('\# Transactions (log)')
plt.ylabel('\# Vulnerabilities')
plt.savefig(os.path.join(ROOT, 'plots/correlation_vulnerabilities_transaction'), dpi=350)
plt.close()


creation_date_ys = {}
creation_date_y = []
unique_creation_date_y = []
sum_cat = {}
sum_contract = 0
sum_unique_contract = 0
creation_dates_x = sorted([*creation_dates])
for creation_date in creation_dates_x:
    for cat in category_creation_date:
        if cat not in sum_cat:
            sum_cat[cat] = 0
        if cat not in creation_date_ys:
            creation_date_ys[cat] = []
        if creation_date in category_creation_date[cat]:
            sum_cat[cat] += len(category_creation_date[cat][creation_date])
        creation_date_ys[cat].append(sum_cat[cat])

    sum_contract += creation_dates[creation_date]
    #creation_date_y.append(sum_contract)
    creation_date_y.append(creation_dates[creation_date])
    
    if creation_date in unique_creation_dates:
        sum_unique_contract += unique_creation_dates[creation_date]
        unique_creation_date_y.append(unique_creation_dates[creation_date])
    else:
        #unique_creation_date_y.append(sum_unique_contract)
        unique_creation_date_y.append(0)


fig, host = plt.subplots()
par1 = host.twinx()
l3, = par1.plot_date([*price_history], [*price_history.values()],ls='-',marker='', color='r', label='\# Price')

l1, = host.plot_date(creation_dates_x, unique_creation_date_y,ls='-',marker='',label='\# Unique Contracts')
l2, = host.plot_date(creation_dates_x, creation_date_y,ls='-',marker='',label='\# All Contracts')

host.set_xlabel('Creation date')
host.set_ylabel('\# Contract')
par1.set_ylabel('Eth Price')

lines = [l1, l2, l3]

host.legend(lines, [l.get_label() for l in lines])
plt.savefig(os.path.join(ROOT, 'plots/creation_date'), dpi=360)
plt.close()

print(sum_cat)

plt.figure(figsize=(6,5))
for cat in sorted(category_creation_date):
    plt.plot_date(creation_dates_x, creation_date_ys[cat],ls='-',marker='',label='\# ' + cat.title().replace('_', ' '))
plt.plot_date(creation_dates_x, creation_date_y,ls='-',marker='',label='\# Contracts')
plt.xlabel('Creation date')
plt.ylabel('\# Contracts')
plt.legend()
plt.savefig(os.path.join(ROOT, 'plots/category_creation_date.pgf'), dpi=360)
plt.close()

plt.figure(figsize=(8,6))
plt.plot_date(correlation_vulnerabilities_date_y, x, 'o', markersize=1)
plt.xlabel('Date')
plt.ylabel('\# vulns')
plt.savefig(os.path.join(ROOT, 'plots/correlation_vulnerabilities_date'), dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot_date(correlation_vulnerabilities_last_transaction_y, x, 'o', markersize=1)
plt.xlabel('Last Transaction')
plt.ylabel('\# vulns')
plt.savefig(os.path.join(ROOT, 'plots/correlation_vulnerabilities_last_transaction'), dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_version_y, x, 'o', markersize=1)
plt.xlabel('Version')
plt.ylabel('\# vulns')
plt.savefig(os.path.join(ROOT, 'plots/correlation_vulnerabilities_version'), dpi=350)
plt.close()

plt.figure(figsize=(8,6))
plt.plot(correlation_vulnerabilities_line_y, x, 'o', markersize=1)
plt.xlabel('\# Lines')
plt.ylabel('\# vulns')
plt.savefig(os.path.join(ROOT, 'plots/correlation_vulnerabilities_line'), dpi=350)
plt.close()