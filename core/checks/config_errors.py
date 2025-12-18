"""
配置错误与信息泄露检查模块
实现6个检查点：
1. .env文件暴露
2. .git/.svn暴露
3. 备份文件泄露（.bak/.zip/.old）
4. 目录列表开启
5. Debug/开发模式开启
6. 错误信息泄露（路径/版本/SQL报错）
"""

import re
import requests
from urllib.parse import urljoin
from typing import Dict, List, Optional, Tuple
from colorama import Fore, Style

class ConfigErrorChecks:
    """配置错误与信息泄露检查类"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.results = []
        
    def check_env_exposure(self, base_url: str) -> Dict:
        """检查.env文件暴露"""
        check_name = ".env文件暴露"
        description = "检测敏感配置文件.env是否可公开访问"
        
        env_paths = [
            '.env',
            '.env.local',
            '.env.production',
            '.env.development',
            'config/.env',
            'app/.env'
        ]
        
        found_paths = []
        for path in env_paths:
            url = urljoin(base_url, path)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    content = response.text[:500]  # 只检查前500字符
                    # 检查是否包含常见的.env内容模式
                    if any(keyword in content.lower() for keyword in 
                           ['database', 'password', 'secret', 'api_key', 'token']):
                        found_paths.append({
                            'url': url,
                            'status': response.status_code,
                            'content_preview': content[:100] + '...' if len(content) > 100 else content
                        })
            except:
                continue
        
        severity = "高危" if found_paths else "低危"
        status = "发现" if found_paths else "未发现"
        
        return {
            'name': check_name,
            'description': description,
            'severity': severity,
            'status': status,
            'details': found_paths if found_paths else "未发现可访问的.env文件",
            'recommendation': "将.env文件移出Web可访问目录，或通过服务器配置禁止访问"
        }
    
    def check_git_svn_exposure(self, base_url: str) -> Dict:
        """检查.git/.svn暴露"""
        check_name = ".git/.svn暴露"
        description = "检测版本控制目录是否可公开访问"
        
        vcs_paths = [
            '.git/',
            '.git/config',
            '.git/HEAD',
            '.svn/',
            '.svn/entries',
            '.hg/',
            '.bzr/'
        ]
        
        found_paths = []
        for path in vcs_paths:
            url = urljoin(base_url, path)
            try:
                response = self.session.head(url, timeout=5)
                if response.status_code == 200:
                    # 对于某些路径，可能需要GET请求确认
                    if path.endswith('config') or path.endswith('HEAD') or path.endswith('entries'):
                        get_response = self.session.get(url, timeout=5)
                        if get_response.status_code == 200:
                            found_paths.append({
                                'path': path,
                                'url': url,
                                'status': get_response.status_code
                            })
                    else:
                        found_paths.append({
                            'path': path,
                            'url': url,
                            'status': response.status_code
                        })
            except:
                continue
        
        severity = "高危" if found_paths else "低危"
        status = "发现" if found_paths else "未发现"
        
        return {
            'name': check_name,
            'description': description,
            'severity': severity,
            'status': status,
            'details': found_paths if found_paths else "未发现可访问的版本控制目录",
            'recommendation': "配置Web服务器禁止访问.git/.svn等目录，或将这些目录移出Web根目录"
        }
    
    def check_backup_files(self, base_url: str) -> Dict:
        """检查备份文件泄露"""
        check_name = "备份文件泄露"
        description = "检测常见的备份文件（.bak/.zip/.old等）是否可公开访问"
        
        backup_extensions = [
            '.bak', '.backup', '.old', '.temp', '.tmp',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.sql', '.dump', '.db', '.mdb',
            '.swp', '.swo', '.swn'  # Vim交换文件
        ]
        
        # 常见备份文件名模式
        backup_patterns = [
            'backup', 'database', 'dump', 'export',
            'config', 'settings', 'web', 'site'
        ]
        
        found_files = []
        
        # 首先检查常见备份文件
        common_backups = [
            'backup.zip', 'backup.tar.gz', 'database.sql', 'dump.sql',
            'config.bak', 'web.bak', 'site.old', 'www.zip'
        ]
        
        for filename in common_backups:
            url = urljoin(base_url, filename)
            try:
                response = self.session.head(url, timeout=5)
                if response.status_code == 200:
                    found_files.append({
                        'filename': filename,
                        'url': url,
                        'status': response.status_code
                    })
            except:
                continue
        
        # 检查当前页面中的链接，查找可能的备份文件
        try:
            response = self.session.get(base_url, timeout=10)
            if response.status_code == 200:
                # 简单查找链接中的备份文件
                for ext in backup_extensions:
                    pattern = rf'href=["\'][^"\']*{re.escape(ext)}["\']'
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    for match in matches:
                        # 提取URL
                        url_match = re.search(r'href=["\']([^"\']+)["\']', match)
                        if url_match:
                            file_url = urljoin(base_url, url_match.group(1))
                            if file_url not in [f['url'] for f in found_files]:
                                found_files.append({
                                    'filename': url_match.group(1).split('/')[-1],
                                    'url': file_url,
                                    'status': '需要验证'
                                })
        except:
            pass
        
        severity = "中危" if found_files else "低危"
        status = "发现" if found_files else "未发现"
        
        return {
            'name': check_name,
            'description': description,
            'severity': severity,
            'status': status,
            'details': found_files if found_files else "未发现明显的备份文件",
            'recommendation': "定期清理Web目录中的备份文件，配置服务器禁止访问特定扩展名文件"
        }
    
    def check_directory_listing(self, base_url: str) -> Dict:
        """检查目录列表开启"""
        check_name = "目录列表开启"
        description = "检测Web服务器是否启用了目录浏览功能"
        
        # 测试常见目录
        test_dirs = [
            'images/', 'img/', 'uploads/', 'files/',
            'assets/', 'static/', 'public/', 'docs/'
        ]
        
        found_dirs = []
        for directory in test_dirs:
            url = urljoin(base_url, directory)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    content = response.text.lower()
                    # 检查是否包含目录列表特征
                    directory_indicators = [
                        'index of', 'directory listing', 'parent directory',
                        '<title>index of', 'last modified', 'size',
                        'name</a>', 'size</a>', 'description</a>'
                    ]
                    
                    if any(indicator in content for indicator in directory_indicators):
                        # 进一步检查是否真的是目录列表（而不是普通页面）
                        if '<html' in content and ('<ul>' in content or '<table' in content):
                            found_dirs.append({
                                'directory': directory,
                                'url': url,
                                'status': response.status_code
                            })
            except:
                continue
        
        severity = "中危" if found_dirs else "低危"
        status = "发现" if found_dirs else "未发现"
        
        return {
            'name': check_name,
            'description': description,
            'severity': severity,
            'status': status,
            'details': found_dirs if found_dirs else "未发现开启目录列表的目录",
            'recommendation': "在Web服务器配置中关闭目录浏览功能（如Apache的Options -Indexes）"
        }
    
    def check_debug_mode(self, base_url: str) -> Dict:
        """检查Debug/开发模式开启"""
        check_name = "Debug/开发模式开启"
        description = "检测应用程序是否处于调试或开发模式"
        
        debug_indicators = []
        
        # 检查常见调试端点
        debug_endpoints = [
            'debug', 'debugger', 'console', 'admin/debug',
            'phpinfo.php', 'info.php', 'test.php',
            '_debug', '_console', 'web-console'
        ]
        
        for endpoint in debug_endpoints:
            url = urljoin(base_url, endpoint)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    content = response.text.lower()
                    # 检查是否包含调试信息
                    if any(keyword in content for keyword in 
                           ['debug', 'phpinfo', 'environment', 'configuration', 'version']):
                        debug_indicators.append({
                            'endpoint': endpoint,
                            'url': url,
                            'status': response.status_code,
                            'indicator': '调试端点可访问'
                        })
            except:
                continue
        
        # 检查响应头中的调试信息
        try:
            response = self.session.get(base_url, timeout=10)
            headers = response.headers
            
            debug_headers = {
                'X-Debug-Token': '调试令牌',
                'X-Debug-Token-Link': '调试令牌链接',
                'X-Powered-By': '服务器技术栈',
                'Server': '服务器信息'
            }
            
            for header, description in debug_headers.items():
                if header in headers:
                    value = headers[header]
                    # 检查是否包含开发/调试信息
                    if any(keyword in value.lower() for keyword in 
                           ['debug', 'dev', 'development', 'test', 'local']):
                        debug_indicators.append({
                            'endpoint': '响应头',
                            'url': base_url,
                            'status': response.status_code,
                            'indicator': f'{header}: {value}'
                        })
        except:
            pass
        
        severity = "高危" if debug_indicators else "低危"
        status = "发现" if debug_indicators else "未发现"
        
        return {
            'name': check_name,
            'description': description,
            'severity': severity,
            'status': status,
            'details': debug_indicators if debug_indicators else "未发现明显的调试模式特征",
            'recommendation': "在生产环境中关闭调试模式，移除调试端点和信息泄露的响应头"
        }
    
    def check_error_leakage(self, base_url: str) -> Dict:
        """检查错误信息泄露"""
        check_name = "错误信息泄露"
        description = "检测应用程序是否泄露敏感错误信息（路径、版本、SQL报错等）"
        
        error_indicators = []
        
        # 测试方法：发送可能引发错误的请求
        test_cases = [
            # 非法参数
            ('GET', {'page': "' OR '1'='1"}),
            ('GET', {'id': "<script>alert(1)</script>"}),
            # 不存在的路径
            ('GET', {'path': '/../../../../etc/passwd'}),
            # 非法文件扩展名
            ('GET', {'file': 'test.php%00.jpg'}),
        ]
        
        for method, params in test_cases:
            try:
                if method == 'GET':
                    response = self.session.get(base_url, params=params, timeout=5)
                else:
                    continue
                
                if response.status_code >= 400 and response.status_code < 600:
                    content = response.text.lower()
                    
                    # 检查是否包含敏感错误信息
                    sensitive_patterns = [
                        (r'stack trace', '堆栈跟踪'),
                        (r'line \d+', '代码行号'),
                        (r'file.*\.php', 'PHP文件路径'),
                        (r'file.*\.py', 'Python文件路径'),
                        (r'file.*\.java', 'Java文件路径'),
                        (r'syntax error', '语法错误'),
                        (r'database error', '数据库错误'),
                        (r'sql.*error', 'SQL错误'),
                        (r'mysql.*error', 'MySQL错误'),
                        (r'postgresql.*error', 'PostgreSQL错误'),
                        (r'version.*\d+\.\d+', '版本信息'),
                        (r'apache.*\d+\.\d+', 'Apache版本'),
                        (r'nginx.*\d+\.\d+', 'Nginx版本'),
                        (r'php.*\d+\.\d+', 'PHP版本'),
                        (r'python.*\d+\.\d+', 'Python版本'),
                    ]
                    
                    for pattern, description in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            error_indicators.append({
                                'test_case': f"{method} with {params}",
                                'status_code': response.status_code,
                                'leakage_type': description,
                                'snippet': content[:200] + '...' if len(content) > 200 else content
                            })
                            break  # 每个测试用例只记录一次泄露
                            
            except Exception as e:
                # 连接错误等不记录
                continue
        
        severity = "中危" if error_indicators else "低危"
        status = "发现" if error_indicators else "未发现"
        
        return {
            'name': check_name,
            'description': description,
            'severity': severity,
            'status': status,
            'details': error_indicators if error_indicators else "未发现明显的错误信息泄露",
            'recommendation': "配置应用程序在生产环境中显示通用错误页面，不泄露堆栈跟踪、文件路径、版本等敏感信息"
        }
    
    def get_checks(self):
        """获取所有检查点"""
        return [
            {'id': 'config_001', 'name': '.env文件暴露', 'category': '配置错误'},
            {'id': 'config_002', 'name': 'Git/SVN信息泄露', 'category': '配置错误'},
            {'id': 'config_003', 'name': '备份文件暴露', 'category': '配置错误'},
            {'id': 'config_004', 'name': '目录遍历/列表', 'category': '配置错误'},
            {'id': 'config_005', 'name': '调试模式开启', 'category': '配置错误'},
            {'id': 'config_006', 'name': '错误信息泄露', 'category': '配置错误'}
        ]
    
    def run_check(self, url, check_id, options):
        """运行指定检查"""
        checks = {
            'config_001': self.check_env_exposure,
            'config_002': self.check_git_svn_exposure,
            'config_003': self.check_backup_files,
            'config_004': self.check_directory_listing,
            'config_005': self.check_debug_mode,
            'config_006': self.check_error_leakage
        }
        
        if check_id in checks:
            try:
                result = checks[check_id](url)
                # 转换结果格式以匹配scanner期望的格式
                status_map = {'发现': 'vulnerable', '未发现': 'safe', '错误': 'error', '不适用': 'info', '信息': 'info'}
                severity_map = {'高危': 'high', '中危': 'medium', '低危': 'low', '未知': 'info', '信息': 'info'}
                
                return {
                    'status': status_map.get(result.get('status', 'unknown'), 'unknown'),
                    'severity': severity_map.get(result.get('severity', 'info'), 'info'),
                    'description': result.get('description', ''),
                    'details': result.get('details', {}),
                    'recommendation': result.get('recommendation', '')
                }
            except Exception as e:
                return {
                    'status': 'error',
                    'severity': 'info',
                    'description': f'检查执行异常: {str(e)}',
                    'details': {},
                    'recommendation': '请检查网络连接或目标服务器状态'
                }
        else:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'未知检查ID: {check_id}',
                'details': {},
                'recommendation': '请检查检查ID是否正确'
            }
    
    def run_all_checks(self, base_url: str) -> List[Dict]:
        """运行所有配置错误检查"""
        print(f"{Fore.CYAN}[*] 开始配置错误与信息泄露检查...{Style.RESET_ALL}")
        
        checks = [
            self.check_env_exposure,
            self.check_git_svn_exposure,
            self.check_backup_files,
            self.check_directory_listing,
            self.check_debug_mode,
            self.check_error_leakage
        ]
        
        results = []
        for check_func in checks:
            try:
                result = check_func(base_url)
                results.append(result)
                
                # 显示进度
                status_color = Fore.RED if result['status'] == '发现' else Fore.GREEN
                print(f"  {status_color}[{result['status'][0]}]{Style.RESET_ALL} {result['name']}")
                
            except Exception as e:
                print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {check_func.__name__} 检查失败: {str(e)}")
                results.append({
                    'name': check_func.__name__,
                    'description': '检查执行失败',
                    'severity': '未知',
                    'status': '错误',
                    'details': str(e),
                    'recommendation': '检查网络连接或目标可达性'
                })
        
        return results

# 导出检查类
__all__ = ['ConfigErrorChecks']
