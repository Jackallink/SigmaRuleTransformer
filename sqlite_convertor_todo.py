# TODO
# Please use splunk_convertor.py which will create more SPLs. There are some Sqlite limits for transformation.
import os
import csv
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

# 初始化 Sigma 转换器
converter = sqliteBackend()

# 指定包含 Sigma 规则的目录
rules_directory = './rules/linux/auditd'
# CSV 文件的字段名
csv_fieldnames = ["Rule Title", "Rule ID", "Rule Description","References","Tags","Logsource","Fields", "SQL Query"]

# 准备 CSV 文件
csv_file_path = os.path.join(rules_directory, 'sigma_to_splunk.csv')

# 确保 CSV 文件存在并打开它
with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=csv_fieldnames)

    # 写入 CSV 文件标题行
    writer.writeheader()

    # 遍历目录，寻找所有 .yaml 文件
    for root, dirs, files in os.walk(rules_directory):
        for file in files:
            if file.endswith('.yml'):
                # 构建文件的完整路径
                file_path = os.path.join(root, file)
                # 读取 YAML 文件内容
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                # 从 YAML 字符串加载 Sigma 规则
                rule = SigmaCollection.from_yaml(yaml_content)
                print(rule)
                # 转换规则为 SQL
                sql_query = converter.convert(rule)
                # 确保转换结果不为空
                if sql_query:
                    # 提取 Sigma 规则的元数据
                    rule_metadata = {
                        "Rule Title": rule.rules[0].title,
                        "Rule ID": rule.rules[0].id,
                        "Rule Description": rule.rules[0].description,
                        "References":rule.rules[0].references,
                        "Tags":rule.rules[0].tags,
                        "Logsource":rule.rules[0].source,
                        "Fields":rule.rules[0].fields
                    }
                    # 将 Sigma 规则的元数据和转换后的 SQL 语句写入 CSV
                    writer.writerow({**rule_metadata, "SQL Query": sql_query})

print(f"CSV file '{csv_file_path}' has been created successfully with Sigma rules and their corresponding SQL queries.")