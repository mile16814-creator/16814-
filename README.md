# 16814-扫描
Windows上的Web安全扫描工具  一个使用python轻量级的Web安全扫描工具，用于自动检测网站中的常见安全漏洞。支持28种安全检查点，提供中文报告输出。  ## 功能特性  - **5大类28项安全检查**
使用方法首先双击 install.bat安装依赖，
然后使用扫描脚本（Windows）
双击 scan.bat
# 或命令行运行
scan.bat https://example.com

# 方法2：直接使用Python
python scanner.py https://example.com

# 批量扫描
python scanner.py -f urls.txt

# 保存报告到文件
python scanner.py https://example.com -o report.txt
或使用python scanner.py --help获得帮助
