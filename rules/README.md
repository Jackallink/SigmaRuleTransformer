Transform Sigma Rules to Different backend.
For now, support splunk_convertor.

* usage
  * `"python splunk_convertor.py your_directory"`
    * for example,`python splunk_convertor.py rules/linux` or `python splunk_convertor.py rules`
    * 便利rules/linux目录下所有包含.yml文件的目录，并生成以最终目录为后缀的csv文件名。
  * 生成字段`"File Name","Rule Title", "Rule ID", "Rule Description", "Chinese Title", "Chinese Description", "Level","References", "Tags","Logsource", "Fields", "FalsePositive", "Error Translation", "Detection", "SPL Query"`
  * `"Title Name"`和`"Rule Description"`通过 `googletrans` lib实现自动翻译为中文。