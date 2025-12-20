#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web安全扫描器核心引擎
"""

import time
import sys
import os
import io
import concurrent.futures
from datetime import datetime

# 安全导入colorama
try:
    from colorama import Fore, Back, Style
    COLORAMA_AVAILABLE = True
except (ImportError, AttributeError):
    COLORAMA_AVAILABLE = False
    class EmptyColor:
        def __getattr__(self, name):
            return ''
    Fore = EmptyColor()
    Back = EmptyColor()
    Style = EmptyColor()

# 安全打印函数
def safe_print(*args, **kwargs):
    """安全的打印函数，处理文件描述符关闭的情况"""
    try:
        print(*args, **kwargs)
    except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
        # 如果打印失败，尝试使用原始stdout
        try:
            if hasattr(sys, '__stdout__'):
                sys.__stdout__.write(' '.join(str(arg) for arg in args) + '\n')
                sys.__stdout__.flush()
        except:
            pass  # 如果所有方法都失败，静默忽略

from .checks import (
    web_vulns,
    config_errors,
    http_security,
    api_security,
    basic_exposure,
    sql_injection
)

class WebSecurityScanner:
    """Web安全扫描器"""
    
    def __init__(self, timeout=10, concurrency=5, user_agent=None, 
                 proxy=None, cookies=None, headers=None, 
                 skip_checks=None, only_checks=None, verbose=False, quiet=False):
        """
        初始化扫描器
        
        Args:
            timeout: 请求超时时间（秒）
            concurrency: 并发请求数
            user_agent: 自定义User-Agent
            proxy: 代理服务器
            cookies: Cookie字符串
            headers: 自定义HTTP头列表
            skip_checks: 跳过的检查类型列表
            only_checks: 只运行的检查类型列表
            verbose: 详细输出模式
            quiet: 安静模式
        """
        self.timeout = timeout
        self.concurrency = concurrency
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.proxy = proxy
        self.cookies = cookies
        self.headers = headers or []
        self.skip_checks = skip_checks or []
        self.only_checks = only_checks or []
        self.verbose = verbose
        self.quiet = quiet
        
        # 创建共享的 requests session
        import requests
        self.session = requests.Session()
        if self.proxy:
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}
        if self.cookies:
            self.session.headers.update({'Cookie': self.cookies})
        if self.headers:
            for header in self.headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    self.session.headers.update({key.strip(): value.strip()})
        self.session.headers.update({'User-Agent': self.user_agent})
        
        # 初始化检查模块
        self.check_modules = {
            'web_vulns': web_vulns.WebVulnerabilityChecks(),
            'config_errors': config_errors.ConfigErrorChecks(self.session),
            'http_security': http_security.HttpSecurityChecks(self.session),
            'api_security': api_security.ApiSecurityChecks(self.session),
            'basic_exposure': basic_exposure.BasicExposureChecks(self.session),
            'sql_injection': sql_injection.SqlInjectionChecks(self.session)
        }
        
        # 所有检查点
        self.all_checks = self._get_all_checks()
    
    def _get_all_checks(self):
        """获取所有检查点"""
        checks = []
        
        for module_name, module in self.check_modules.items():
            module_checks = module.get_checks()
            for check in module_checks:
                check['module'] = module_name
                checks.append(check)
        
        return checks
    
    def scan(self, url):
        """
        执行安全扫描
        
        Args:
            url: 目标URL
            
        Returns:
            扫描结果列表
        """
        if not self.quiet:
            safe_print(f"{Fore.CYAN}开始扫描: {url}")
            safe_print(f"{Fore.WHITE}检查项总数: {len(self.all_checks)}")
        
        results = []
        start_time = time.time()
        
        # 过滤检查点
        checks_to_run = self._filter_checks()
        
        if not self.quiet:
            safe_print(f"{Fore.WHITE}实际运行检查: {len(checks_to_run)}")
        
        # 执行扫描
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_check = {}
            
            for check in checks_to_run:
                future = executor.submit(
                    self._run_check,
                    url,
                    check
                )
                future_to_check[future] = check
            
            # 处理结果
            completed = 0
            for future in concurrent.futures.as_completed(future_to_check):
                check = future_to_check[future]
                completed += 1
                
                try:
                    result = future.result(timeout=self.timeout + 5)
                    results.append(result)
                    
                    if self.verbose and not self.quiet:
                        self._print_check_result(result, completed, len(checks_to_run))
                        
                except Exception as e:
                    error_result = {
                        'id': check['id'],
                        'name': check['name'],
                        'category': check['category'],
                        'module': check['module'],
                        'status': 'error',
                        'severity': 'info',
                        'description': f'检查执行出错: {str(e)}',
                        'details': {},
                        'recommendation': '请检查网络连接或目标服务器状态'
                    }
                    results.append(error_result)
        
        # 计算扫描时间
        scan_time = time.time() - start_time
        
        if not self.quiet:
            safe_print(f"{Fore.GREEN}扫描完成! 耗时: {scan_time:.2f}秒")
        
        return results
    
    def _filter_checks(self):
        """过滤检查点"""
        checks = self.all_checks
        
        # 如果指定了only_checks，只运行这些检查
        if self.only_checks:
            checks = [c for c in checks if c['module'] in self.only_checks]
        
        # 跳过指定的检查
        if self.skip_checks:
            checks = [c for c in checks if c['module'] not in self.skip_checks]
        
        return checks
    
    def _run_check(self, url, check):
        """执行单个检查"""
        try:
            module = self.check_modules[check['module']]
            result = module.run_check(url, check['id'], {
                'timeout': self.timeout,
                'user_agent': self.user_agent,
                'proxy': self.proxy,
                'cookies': self.cookies,
                'headers': self.headers
            })
            
            return {
                'id': check['id'],
                'name': check['name'],
                'category': check['category'],
                'module': check['module'],
                'status': result.get('status', 'unknown'),
                'severity': result.get('severity', 'info'),
                'description': result.get('description', ''),
                'details': result.get('details', {}),
                'recommendation': result.get('recommendation', ''),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            return {
                'id': check['id'],
                'name': check['name'],
                'category': check['category'],
                'module': check['module'],
                'status': 'error',
                'severity': 'info',
                'description': f'检查执行异常: {str(e)}',
                'details': {},
                'recommendation': '请检查检查模块实现',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def _print_check_result(self, result, current, total):
        """打印检查结果"""
        status_colors = {
            'vulnerable': Fore.RED,
            'suspicious': Fore.YELLOW,
            'safe': Fore.GREEN,
            'info': Fore.BLUE,
            'error': Fore.MAGENTA,
            'unknown': Fore.WHITE
        }
        
        severity_symbols = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'info': '🔵'
        }
        
        status_color = status_colors.get(result['status'], Fore.WHITE)
        severity_symbol = severity_symbols.get(result['severity'], '⚪')
        
        progress = f"[{current}/{total}]"
        status_display = f"{severity_symbol} {result['status'].upper()}"
        
        safe_print(f"{Fore.WHITE}{progress} {status_color}{status_display} {Fore.WHITE}{result['name']}")
    
    def print_results(self, results):
        """打印扫描结果"""
        if not results:
            safe_print(f"{Fore.YELLOW}未获取到扫描结果")
            return
        
        # 按严重程度分组
        critical_results = [r for r in results if r['severity'] == 'critical' and r['status'] == 'vulnerable']
        high_results = [r for r in results if r['severity'] == 'high' and r['status'] == 'vulnerable']
        medium_results = [r for r in results if r['severity'] == 'medium' and r['status'] == 'vulnerable']
        low_results = [r for r in results if r['severity'] == 'low' and r['status'] == 'vulnerable']
        info_results = [r for r in results if r['status'] in ['info', 'safe', 'suspicious', 'error', 'unknown']]
        
        safe_print(f"\n{Fore.CYAN}{'='*60}")
        safe_print(f"{Fore.YELLOW}扫描结果摘要")
        safe_print(f"{Fore.CYAN}{'='*60}")
        
        safe_print(f"{Fore.RED}🔴 严重漏洞: {len(critical_results)}个")
        safe_print(f"{Fore.YELLOW}🟠 高危漏洞: {len(high_results)}个")
        safe_print(f"{Fore.YELLOW}🟡 中危漏洞: {len(medium_results)}个")
        safe_print(f"{Fore.GREEN}🟢 低危漏洞: {len(low_results)}个")
        safe_print(f"{Fore.BLUE}🔵 其他信息: {len(info_results)}个")
        
        # 显示严重漏洞详情
        if critical_results:
            safe_print(f"\n{Fore.RED}{'='*60}")
            safe_print(f"{Fore.RED}🔴 严重漏洞详情")
            safe_print(f"{Fore.RED}{'='*60}")
            for result in critical_results:
                safe_print(f"\n{Fore.RED}▶ {result['name']}")
                safe_print(f"{Fore.WHITE}   描述: {result['description']}")
                if result.get('details'):
                    if isinstance(result['details'], dict):
                        for key, value in result['details'].items():
                            safe_print(f"{Fore.WHITE}   {key}: {value}")
                    else:
                        safe_print(f"{Fore.WHITE}   详情: {result['details']}")
                safe_print(f"{Fore.WHITE}   建议: {result['recommendation']}")
        
        # 显示高危漏洞详情
        if high_results:
            safe_print(f"\n{Fore.YELLOW}{'='*60}")
            safe_print(f"{Fore.YELLOW}🟠 高危漏洞详情")
            safe_print(f"{Fore.YELLOW}{'='*60}")
            for result in high_results:
                safe_print(f"\n{Fore.YELLOW}▶ {result['name']}")
                safe_print(f"{Fore.WHITE}   描述: {result['description']}")
                if result.get('details'):
                    if isinstance(result['details'], dict):
                        for key, value in result['details'].items():
                            safe_print(f"{Fore.WHITE}   {key}: {value}")
                    else:
                        safe_print(f"{Fore.WHITE}   详情: {result['details']}")
                safe_print(f"{Fore.WHITE}   建议: {result['recommendation']}")
        
        # 显示中危漏洞详情（medium severity）
        if medium_results:
            safe_print(f"\n{Fore.YELLOW}{'='*60}")
            safe_print(f"{Fore.YELLOW}🟡 中危漏洞详情")
            safe_print(f"{Fore.YELLOW}{'='*60}")
            for result in medium_results:
                safe_print(f"\n{Fore.YELLOW}▶ {result['name']}")
                safe_print(f"{Fore.WHITE}   描述: {result['description']}")
                if result.get('details'):
                    if isinstance(result['details'], dict):
                        for key, value in result['details'].items():
                            safe_print(f"{Fore.WHITE}   {key}: {value}")
                    else:
                        safe_print(f"{Fore.WHITE}   详情: {result['details']}")
                safe_print(f"{Fore.WHITE}   建议: {result['recommendation']}")
        
        # 显示低危漏洞详情
        if low_results:
            safe_print(f"\n{Fore.GREEN}{'='*60}")
            safe_print(f"{Fore.GREEN}🟢 低危漏洞详情")
            safe_print(f"{Fore.GREEN}{'='*60}")
            for result in low_results:
                safe_print(f"\n{Fore.GREEN}▶ {result['name']}")
                safe_print(f"{Fore.WHITE}   描述: {result['description']}")
                if result.get('details'):
                    if isinstance(result['details'], dict):
                        for key, value in result['details'].items():
                            safe_print(f"{Fore.WHITE}   {key}: {value}")
                    else:
                        safe_print(f"{Fore.WHITE}   详情: {result['details']}")
                safe_print(f"{Fore.WHITE}   建议: {result['recommendation']}")
        
        # 显示其他信息详情
        if info_results:
            safe_print(f"\n{Fore.BLUE}{'='*60}")
            safe_print(f"{Fore.BLUE}🔵 其他信息详情")
            safe_print(f"{Fore.BLUE}{'='*60}")
            for result in info_results:
                # 根据状态选择颜色
                if result['status'] == 'safe':
                    status_color = Fore.GREEN
                    status_text = '✓ 安全'
                elif result['status'] == 'suspicious':
                    status_color = Fore.YELLOW
                    status_text = '⚠ 可疑'
                elif result['status'] == 'info':
                    status_color = Fore.BLUE
                    status_text = 'ℹ 信息'
                elif result['status'] == 'error':
                    status_color = Fore.MAGENTA
                    status_text = '✗ 错误'
                elif result['status'] == 'unknown':
                    status_color = Fore.WHITE
                    status_text = '? 未知'
                else:
                    status_color = Fore.WHITE
                    status_text = result['status']
                
                safe_print(f"\n{status_color}▶ [{status_text}] {result['name']}")
                safe_print(f"{Fore.WHITE}   描述: {result['description']}")
                if result.get('details'):
                    if isinstance(result['details'], dict):
                        for key, value in result['details'].items():
                            safe_print(f"{Fore.WHITE}   {key}: {value}")
                    else:
                        safe_print(f"{Fore.WHITE}   详情: {result['details']}")
                if result.get('recommendation'):
                    safe_print(f"{Fore.WHITE}   建议: {result['recommendation']}")
        
        # 计算安全评分
        total_vulns = len(critical_results) + len(high_results) + len(medium_results) + len(low_results)
        if total_vulns == 0:
            score = 100
        else:
            score = max(0, 100 - (len(critical_results) * 20 + len(high_results) * 10 + 
                                 len(medium_results) * 5 + len(low_results) * 2))
        
        safe_print(f"\n{Fore.CYAN}{'='*60}")
        safe_print(f"{Fore.YELLOW}安全评分: {score}/100")
        
        if score >= 80:
            safe_print(f"{Fore.GREEN}安全状态: 良好")
        elif score >= 60:
            safe_print(f"{Fore.YELLOW}安全状态: 一般")
        else:
            safe_print(f"{Fore.RED}安全状态: 较差，建议立即修复")
        
        safe_print(f"{Fore.CYAN}{'='*60}")
