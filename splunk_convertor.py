import argparse
import os
import csv
import yaml
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from googletrans import Translator

parser = argparse.ArgumentParser(description='Generate CSV files for Sigma rules in directories.')
parser.add_argument('directory', type=str, help='The directory containing Sigma rule files.')
args = parser.parse_args()
# 初始化 Sigma 转换器
converter = SplunkBackend()
# 创建一个翻译器实例
translator = Translator()
# 指定包含 Sigma 规则的目录
# file_dir = "process_creation"
# 设置命令行参数解析


# 指定包含 Sigma 规则的目录
rules_directory = args.directory

csv_fieldnames = ["File Name",
                  "Rule Title", "Rule ID", "Rule Description", "Chinese Title", "Chinese Description", "Level",
                  "References", "Tags",
                  "Logsource", "Fields", "FalsePositive", "Error Translation", "Detection", "SPL Query"
                  ]




for root, dirs, files in os.walk(rules_directory):
    # 检查当前目录中的文件，跳过没有 YAML 文件的目录
    if not any(file.endswith('.yml') for file in files):
        print(f"No YAML files found in {root}. Skipping directory.")
        continue  # 跳过当前目录，继续下一个迭代
        # 使用当前目录作为 CSV 文件的目录
    csv_file_dir = root
    file_dir = os.path.relpath(csv_file_dir, rules_directory)  # 获取相对于主目录的路径
    csv_file_path = os.path.join(csv_file_dir, f'Sigma2SplunkSPL_{os.path.basename(file_dir)}.csv')
    with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fieldnames)
        writer.writeheader()
        for file in files:
            if file.endswith('.yml'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
                    rule_data = yaml.safe_load(yaml_content)
                    print(yaml_content)
                    rule = SigmaCollection.from_yaml(yaml_content)
                    try:
                        spl_query = converter.convert(rule)
                        try:
                            translated_title = translator.translate(rule.rules[0].title, src='en', dest='zh-cn').text
                            translated_description = translator.translate(rule.rules[0].description, src='en',
                                                                          dest='zh-cn').text
                        except Exception as e:
                            print(f"Error translating {file}: {e} \n{yaml_content}")
                            print(yaml_content)
                            translated_title = rule.rules[0].title
                            translated_description = rule.rules[0].description

                        # 从 Sigma 规则中提取元数据
                        rule_metadata = {
                            "File Name": file,
                            "Rule Title": rule.rules[0].title,
                            "Rule ID": str(rule.rules[0].id),  # 确保 ID 是字符串格式
                            "Chinese Title": translated_title,
                            "Chinese Description": translated_description,
                            "Rule Description": rule.rules[0].description,
                            "Level": rule.rules[0].level,
                            "References": ', '.join(rule.rules[0].references) if rule.rules[0].references else '',
                            # 格式化 tags 列表
                            "Tags": ', '.join([tag.namespace + '.' + tag.name for tag in rule.rules[0].tags]),
                            # 提取 logsource 信息
                            "Logsource": f"product: {rule.rules[0].logsource.product}, service: {rule.rules[0].logsource.service}",
                            "Fields": ', '.join(rule.rules[0].fields) if rule.rules[0].fields else '',
                            "FalsePositive": rule.rules[0].falsepositives,
                            "Error Translation": '',
                            "Detection": rule_data.get('detection')
                        }

                    except Exception as e:
                        print(f"Error Parsing SPL {file}: {e}\n{yaml_content}")
                        print(rule_data)
                        try:
                            translated_title = translator.translate(rule_data.get('title'), src='en', dest='zh-cn').text
                            translated_description = translator.translate(rule_data.get('description'), src='en',
                                                                          dest='zh-cn').text
                        except Exception as e:
                            print(f"Error translating {file}: {e}")
                            translated_title = rule_data.get('description')
                            translated_description = rule_data.get('description')
                        rule_metadata = {
                            "File Name": file,
                            "Rule Title": rule_data.get('title'),
                            "Rule ID": rule_data.get('id'),  # 确保 ID 是字符串格式
                            "Rule Description": rule_data.get('description'),
                            "Chinese Title": translated_title,
                            "Chinese Description": translated_description,
                            "Level": rule_data.get('level'),
                            "References": rule_data.get('references'),
                            "Tags": rule_data.get('tags'),
                            "Logsource": rule_data.get('logsource'),
                            "Fields": '',
                            "FalsePositive": rule_data.get('falsepositives'),
                            "Error Translation": e,
                            "Detection": rule_data.get('detection'),
                        }
                        spl_query = ["To Do"]

                    # 转换规则为 SPL
                    if spl_query:
                        writer.writerow({**rule_metadata, "SPL Query": spl_query[0]})

print(f"Sigma2SplunkSPL_xxx.csv files have been created successfully in '{rules_directory}' and it's sub-directorys.")