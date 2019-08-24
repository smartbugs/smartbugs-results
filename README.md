# SmartBugs Vulnerability Analysis

This repository contains the RAW results of the vulnerability analysis of 9 tools on 47,587 smart contracts.
We used two datasets of vulnerabilities: 1) 69 annotated vulnerable contracts 2) 47,518 contracts from the Ethereum network.

The raw results of the analysis on the first benchmark is stored in `results/<name_tool>/curated/<contract_name>`.
The raw results of the analysis on the first benchmark is stored in `results/<name_tool>/icse20/<contract_address>`.

## Structure of the repository

```
├─ metadata
│  ├─ balances.json
│  ├─ duplicates.json
│  ├─ eth_price.json
│  ├─ nb_lines.csv
│  ├─ results_curated.json
│  ├─ results_wild.json
│  ├─ unique_contracts.csv
│  ├─ vulnerabilities.json
│  └─ vulnerabilities_mapping.csv
├─ plots
│  └─ <plot_name>.png
├─ results
│  └─ <tool_name>
│     └─ <dataset_name>
│        └─ <contract_address>
│           ├─ <result.log>  # stdout of the analysis
│           └─ <result.json> # parsable output analysis
├─ script
│  ├─ combine_appraoches.py
│  ├─ generate_plot.py
│  ├─ generate_results_curated.py
│  └─ generate_results_wild.py

```

## SB Curated Results

# Execution Time Stat

|  #  | Tool       | Avg. Execution Time | Total Execution Time |
| --- | ---------- | ------------------- | -------------------- |
|   1 | Honeybadger | 0:00:46    | 0:53:11    |
|   2 | Maian      | 0:02:57    | 3:23:50    |
|   3 | Manticore  | 0:08:11    | 5:03:04    |
|   4 | Mythril    | 0:01:13    | 1:23:42    |
|   5 | Osiris     | 0:00:44    | 0:50:03    |
|   6 | Oyente     | 0:00:36    | 0:41:29    |
|   7 | Securify   | 0:01:00    | 1:09:08    |
|   8 | Slither    | 0:00:03    | 0:03:35    |
|   9 | Smartcheck | 0:00:06    | 0:06:34    |

Total: 13:34:37

# Accuracy

|  Category           | Honeybadger |    Maian    |  Manticore  |   Mythril   |   Osiris    |   Oyente    |  Securify   |   Slither   | Smartcheck  |    Total    |
| ------------------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Access Control      |   0/19   0% |   0/19   0% |   4/19  21% |   4/19  21% |   0/19   0% |   0/19   0% |   0/19   0% |   4/19  21% |   2/19  11% |   5/19  26% |
| Arithmetic          |   0/22   0% |   0/22   0% |   4/22  18% |  15/22  68% |  11/22  50% |  12/22  55% |   0/22   0% |   0/22   0% |   1/22   5% |  19/22  86% |
| Denial Service      |    0/7   0% |    0/7   0% |    0/7   0% |    0/7   0% |    0/7   0% |    0/7   0% |    0/7   0% |    0/7   0% |    0/7   0% |   0/ 7   0% |
| Front Running       |    0/7   0% |    0/7   0% |    0/7   0% |    2/7  29% |    0/7   0% |    0/7   0% |    2/7  29% |    0/7   0% |    0/7   0% |   2/ 7  29% |
| Reentrancy          |    0/8   0% |    0/8   0% |    2/8  25% |    5/8  62% |    5/8  62% |    5/8  62% |    5/8  62% |    7/8  88% |    5/8  62% |   7/ 8  88% |
| Time Manipulation   |    0/5   0% |    0/5   0% |    1/5  20% |    0/5   0% |    0/5   0% |    0/5   0% |    0/5   0% |    2/5  40% |    1/5  20% |   3/ 5  60% |
| Unchecked Low Calls |   0/12   0% |   0/12   0% |   2/12  17% |   5/12  42% |   0/12   0% |   0/12   0% |   3/12  25% |   4/12  33% |   4/12  33% |   9/12  75% |
| Other               |    2/3  67% |    0/3   0% |    0/3   0% |    0/3   0% |    0/3   0% |    0/3   0% |    0/3   0% |    3/3 100% |    0/3   0% |   3/ 3 100% |
| Total               |  2/115   2% |  0/115   0% | 13/115  11% | 31/115  27% | 16/115  14% | 17/115  15% | 10/115   9% | 20/115  17% | 13/115  11% | 48/115  42% |

# Nb Detected Vulnerabilities

| Category            | Honeybadger |    Maian    |  Manticore  |   Mythril   |   Osiris    |   Oyente    |  Securify   |   Slither   | Smartcheck  |    Total    |
| ------------------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Access Control      |           0 |          10 |          28 |          24 |           0 |           0 |           6 |          20 |           3 |          91 |
| Arithmetic          |           0 |           0 |          11 |          92 |          62 |          69 |           0 |           0 |          23 |         257 |
| Denial Service      |           0 |           0 |           0 |           0 |          27 |          11 |           0 |           2 |          19 |          59 |
| Front Running       |           0 |           0 |           0 |          21 |           0 |           0 |          55 |           0 |           0 |          76 |
| Reentrancy          |           0 |           0 |           4 |          16 |           5 |           5 |          32 |          15 |           7 |          84 |
| Time Manipulation   |           0 |           0 |           4 |           0 |           4 |           5 |           0 |           5 |           2 |          20 |
| Unchecked Low Calls |           0 |           0 |           4 |          30 |           0 |           0 |          21 |          13 |          14 |          82 |
| Other               |           5 |           2 |          25 |          32 |           0 |           0 |           0 |          28 |           8 |         100 |
| Total               |           5 |          12 |          76 |         215 |          98 |          90 |         114 |          83 |          76 |         769 |

# Combine tools 
|             | Honeybadger |    Maian    |  Manticore  |   Mythril   |   Osiris    |   Oyente    |  Securify   |   Slither   | Smartcheck  |
| ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Honeybadger |             | 2/115    2% | 15/115  13% | 33/115  29% | 18/115  16% | 19/115  17% | 12/115  10% | 20/115  17% | 15/115  13% |
| Maian       |             |             | 13/115  11% | 31/115  27% | 16/115  14% | 17/115  15% | 10/115   9% | 20/115  17% | 13/115  11% |
| Manticore   |             |             |             | 32/115  28% | 26/115  23% | 26/115  23% | 19/115  17% | 27/115  23% | 20/115  17% |
| Mythril     |             |             |             |             | 33/115  29% | 33/115  29% | 31/115  27% | 42/115  37% | 33/115  29% |
| Osiris      |             |             |             |             |             | 22/115  19% | 21/115  18% | 31/115  27% | 23/115  20% |
| Oyente      |             |             |             |             |             |             | 22/115  19% | 32/115  28% | 25/115  22% |
| Securify    |             |             |             |             |             |             |             | 25/115  22% | 16/115  14% |
| Slither     |             |             |             |             |             |             |             |             | 25/115  22% |
| Smartcheck  |             |             |             |             |             |             |             |             |             |


## SB Wild 

# Execution Time Stat

|  #  | Tool       | Avg. Execution Time | Total Execution Time |
| --- | ---------- | ------------------- | -------------------- |
|   1 | Honeybadger | 0:01:38    | 23 days, 13:40:00 |
|   2 | Maian      | 0:05:16    | 49 days, 10:06:15 |
|   3 | Manticore  | 0:24:28    | 184 days, 1:59:02 |
|   4 | Mythril    | 0:01:24    | 46 days, 7:46:55 |
|   5 | Osiris     | 0:00:34    | 18 days, 10:19:01 |
|   6 | Oyente     | 0:00:30    | 16 days, 4:50:11 |
|   7 | Securify   | 0:06:37    | 217 days, 22:46:26 |
|   8 | Slither    | 0:00:05    | 2 days, 15:09:36 |
|   9 | Smartcheck | 0:00:10    | 5 days, 12:33:14 |

Total: 564 days, 3:10:39

# Nb Detected Vulnerabilities

| Category            | Honeybadger |    Maian    |  Manticore  |   Mythril   |   Osiris    |   Oyente    |  Securify   |   Slither   | Smartcheck  |    Total    |
| ------------------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Access Control      | 0 0.00%     | 44 0.09%    | 47 0.10%    | 1076 2.27%  | 0 0.00%     | 2 0.00%     | 614 1.29%   | 2356 4.97%  | 384 0.81%   | 3801 8.01%  |
| Arithmetic          | 1 0.00%     | 0 0.00%     | 102 0.21%   | 18515 39.02% | 13922 29.34% | 34306 72.30% | 0 0.00%     | 0 0.00%     | 7430 15.66% | 37597 79.23% |
| Denial Service      | 0 0.00%     | 0 0.00%     | 0 0.00%     | 0 0.00%     | 485 1.02%   | 880 1.85%   | 0 0.00%     | 2555 5.38%  | 11621 24.49% | 12419 26.17% |
| Front Running       | 0 0.00%     | 0 0.00%     | 0 0.00%     | 2015 4.25%  | 0 0.00%     | 0 0.00%     | 7217 15.21% | 0 0.00%     | 0 0.00%     | 8161 17.20% |
| Reentrancy          | 19 0.04%    | 0 0.00%     | 2 0.00%     | 8454 17.82% | 496 1.05%   | 308 0.65%   | 2033 4.28%  | 8764 18.47% | 847 1.78%   | 14747 31.08% |
| Time Manipulation   | 0 0.00%     | 0 0.00%     | 90 0.19%    | 0 0.00%     | 1470 3.10%  | 1452 3.06%  | 0 0.00%     | 1988 4.19%  | 68 0.14%    | 4069 8.58%  |
| Unchecked Low Calls | 0 0.00%     | 0 0.00%     | 4 0.01%     | 443 0.93%   | 0 0.00%     | 0 0.00%     | 592 1.25%   | 12199 25.71% | 2867 6.04%  | 14656 30.89% |
| Other               | 26 0.05%    | 135 0.28%   | 1032 2.17%  | 11126 23.45% | 0 0.00%     | 0 0.00%     | 561 1.18%   | 9133 19.25% | 14113 29.74% | 28355 59.76% |
| Total               | 46 0.10%    | 179 0.38%   | 1203 2.54%  | 22994 48.46% | 14665 30.91% | 34764 73.26% | 8781 18.51% | 22269 46.93% | 24906 52.49% | 44589 93.97% |
