#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web安全扫描工具 - 轻量级漏洞扫描器
支持28种常见安全漏洞检测
"""

import argparse
import sys
import os
import io
import time
from datetime import datetime
from colorama import init, Fore, Back, Style

# 设置控制台编码为UTF-8（解决Windows中文乱码问题）
if sys.platform == 'win32':
    # Windows系统设置控制台编码
    try:
        # 检查文件描述符是否可用
        if sys.stdout.isatty() and hasattr(sys.stdout, 'buffer'):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        if sys.stderr.isatty() and hasattr(sys.stderr, 'buffer'):
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
        os.system('chcp 65001 > nul')  # 设置控制台代码页为UTF-8
    except (AttributeError, OSError, ValueError):
        # 如果文件描述符不可用，跳过重新包装
        pass

# 检查文件描述符是否可用
def is_fd_available():
    """检查文件描述符是否可用"""
    try:
        if hasattr(sys.stdout, 'fileno'):
            fd = sys.stdout.fileno()
            if fd >= 0:
                os.isatty(fd)
                return True
    except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
        pass
    return False

# 初始化colorama（安全初始化）
COLORAMA_AVAILABLE = False
if is_fd_available():
    try:
        init(autoreset=True)
        COLORAMA_AVAILABLE = True
    except (OSError, ValueError, AttributeError):
        COLORAMA_AVAILABLE = False

# 如果colorama不可用，创建空颜色对象
if not COLORAMA_AVAILABLE:
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

# 导入核心模块
from core.scanner import WebSecurityScanner
from report.generator import ReportGenerator

def print_banner():
    """打印程序横幅"""
    if COLORAMA_AVAILABLE:
        banner = f"""
{Fore.CYAN}{'='*60}
{Fore.YELLOW}        Web安全扫描工具 v1.0
{Fore.CYAN}{'='*60}
{Fore.WHITE}描述: 轻量级Web安全漏洞扫描器
{Fore.WHITE}支持: 28种常见安全漏洞检测
{Fore.WHITE}作者: 安全扫描工具
{Fore.WHITE}时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Fore.CYAN}{'='*60}
    """
    else:
        banner = f"""
{'='*60}
        Web安全扫描工具 v1.0
{'='*60}
描述: 轻量级Web安全漏洞扫描器
支持: 28种常见安全漏洞检测
作者: 安全扫描工具
时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}
    """
    safe_print(banner)

def print_help():
    """打印帮助信息"""
    if COLORAMA_AVAILABLE:
        help_text = f"""
{Fore.GREEN}使用方法:
{Fore.WHITE}  python scanner.py [URL] [选项]

{Fore.GREEN}示例:
{Fore.WHITE}  python scanner.py https://example.com
{Fore.WHITE}  python scanner.py https://example.com -t 30 --verbose
{Fore.WHITE}  python scanner.py -f urls.txt -o report.html

{Fore.GREEN}选项:
{Fore.WHITE}  -h, --help            显示此帮助信息
{Fore.WHITE}  -f, --file FILE       从文件读取URL列表
{Fore.WHITE}  -t, --timeout SEC     请求超时时间（默认: 10秒）
{Fore.WHITE}  -c, --concurrency NUM 并发请求数（默认: 5）
{Fore.WHITE}  --user-agent AGENT    自定义User-Agent
{Fore.WHITE}  --proxy PROXY         使用代理服务器
{Fore.WHITE}  --cookie COOKIE       添加Cookie
{Fore.WHITE}  --header HEADER       添加自定义HTTP头（格式: "Header: Value"）
{Fore.WHITE}  --skip-checks LIST    跳过的检查类型（逗号分隔）
{Fore.WHITE}  --only-checks LIST    只运行指定检查（逗号分隔）
{Fore.WHITE}  -v, --verbose         详细输出模式
{Fore.WHITE}  -q, --quiet           安静模式（只显示结果）
{Fore.WHITE}  -o, --output FILE     输出报告到文件（HTML格式）

{Fore.GREEN}检查类型:
{Fore.WHITE}  web_vulns      Web漏洞（XSS, CSRF等）
{Fore.WHITE}  config_errors  配置错误/信息泄露
{Fore.WHITE}  http_security  HTTP/会话安全
{Fore.WHITE}  api_security   API安全漏洞
{Fore.WHITE}  basic_exposure 基础暴露面/轻量扫描
    """
    else:
        help_text = f"""
使用方法:
  python scanner.py [URL] [选项]

示例:
  python scanner.py https://example.com
  python scanner.py https://example.com -t 30 --verbose
  python scanner.py -f urls.txt -o report.html

选项:
  -h, --help            显示此帮助信息
  -f, --file FILE       从文件读取URL列表
  -t, --timeout SEC     请求超时时间（默认: 10秒）
  -c, --concurrency NUM 并发请求数（默认: 5）
  --user-agent AGENT    自定义User-Agent
  --proxy PROXY         使用代理服务器
  --cookie COOKIE       添加Cookie
  --header HEADER       添加自定义HTTP头（格式: "Header: Value"）
  --skip-checks LIST    跳过的检查类型（逗号分隔）
  --only-checks LIST    只运行指定检查（逗号分隔）
  -v, --verbose         详细输出模式
  -q, --quiet           安静模式（只显示结果）
  -o, --output FILE     输出报告到文件（HTML格式）

检查类型:
  web_vulns      Web漏洞（XSS, CSRF等）
  config_errors  配置错误/信息泄露
  http_security  HTTP/会话安全
  api_security   API安全漏洞
  basic_exposure 基础暴露面/轻量扫描
    """
    safe_print(help_text)

def parse_args_simple():
    """简单的参数解析器，用于argparse失败时的备用方案"""
    args = type('Args', (), {})()
    args.url = None
    args.file = None
    args.timeout = 10
    args.concurrency = 5
    args.user_agent = None
    args.proxy = None
    args.cookie = None
    args.header = None
    args.skip_checks = None
    args.only_checks = None
    args.verbose = False
    args.quiet = False
    args.output = None
    args.help = False
    
    # 简单解析参数
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ['-h', '--help']:
            args.help = True
        elif arg in ['-f', '--file']:
            i += 1
            args.file = sys.argv[i] if i < len(sys.argv) else None
        elif arg in ['-t', '--timeout']:
            i += 1
            try:
                args.timeout = int(sys.argv[i]) if i < len(sys.argv) else 10
            except (ValueError, IndexError):
                args.timeout = 10
        elif arg in ['-c', '--concurrency']:
            i += 1
            try:
                args.concurrency = int(sys.argv[i]) if i < len(sys.argv) else 5
            except (ValueError, IndexError):
                args.concurrency = 5
        elif arg == '--user-agent':
            i += 1
            args.user_agent = sys.argv[i] if i < len(sys.argv) else None
        elif arg == '--proxy':
            i += 1
            args.proxy = sys.argv[i] if i < len(sys.argv) else None
        elif arg == '--cookie':
            i += 1
            args.cookie = sys.argv[i] if i < len(sys.argv) else None
        elif arg == '--header':
            i += 1
            if args.header is None:
                args.header = []
            args.header.append(sys.argv[i] if i < len(sys.argv) else None)
        elif arg == '--skip-checks':
            i += 1
            args.skip_checks = sys.argv[i] if i < len(sys.argv) else None
        elif arg == '--only-checks':
            i += 1
            args.only_checks = sys.argv[i] if i < len(sys.argv) else None
        elif arg in ['-v', '--verbose']:
            args.verbose = True
        elif arg in ['-q', '--quiet']:
            args.quiet = True
        elif arg in ['-o', '--output']:
            i += 1
            args.output = sys.argv[i] if i < len(sys.argv) else None
        elif not arg.startswith('-') and args.url is None:
            args.url = arg
        i += 1
    
    return args

def main():
    """主函数"""
    # 由于Python 3.14的argparse在文件描述符不可用时会出错，
    # 我们直接使用简单解析器来避免这个问题
    # 如果需要argparse的功能，可以在文件描述符可用时再启用
    
    # 检查文件描述符是否可用
    can_use_argparse = False
    try:
        # 检查stdout和stderr是否可用且未关闭
        if hasattr(sys.stdout, 'fileno'):
            fd = sys.stdout.fileno()
            if fd >= 0:
                # 尝试检查文件描述符是否真的可用
                os.isatty(fd)
                can_use_argparse = True
    except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
        can_use_argparse = False
    
    if can_use_argparse:
        # 尝试使用argparse
        try:
            # 设置环境变量禁用argparse的颜色（Python 3.14+）
            original_no_color = os.environ.get('NO_COLOR')
            original_python_no_color = os.environ.get('PYTHON_ARGCOMPLETE_NO_COLOR')
            try:
                os.environ['NO_COLOR'] = '1'
                os.environ['PYTHON_ARGCOMPLETE_NO_COLOR'] = '1'
                
                parser = argparse.ArgumentParser(
                    description='Web安全扫描工具 - 轻量级漏洞扫描器',
                    add_help=False
                )
                
                # 基本参数
                parser.add_argument('url', nargs='?', help='要扫描的目标URL')
                parser.add_argument('-h', '--help', action='store_true', help='显示帮助信息')
                
                # 输入选项
                parser.add_argument('-f', '--file', help='从文件读取URL列表')
                
                # 扫描选项
                parser.add_argument('-t', '--timeout', type=int, default=10, help='请求超时时间（秒）')
                parser.add_argument('-c', '--concurrency', type=int, default=5, help='并发请求数')
                parser.add_argument('--user-agent', help='自定义User-Agent')
                parser.add_argument('--proxy', help='使用代理服务器')
                parser.add_argument('--cookie', help='添加Cookie')
                parser.add_argument('--header', action='append', help='添加自定义HTTP头')
                
                # 检查选项
                parser.add_argument('--skip-checks', help='跳过的检查类型（逗号分隔）')
                parser.add_argument('--only-checks', help='只运行指定检查（逗号分隔）')
                
                # 输出选项
                parser.add_argument('-v', '--verbose', action='store_true', help='详细输出模式')
                parser.add_argument('-q', '--quiet', action='store_true', help='安静模式')
                parser.add_argument('-o', '--output', help='输出报告到文件')
                
                args = parser.parse_args()
            finally:
                # 恢复原始环境变量
                if original_no_color is None:
                    os.environ.pop('NO_COLOR', None)
                else:
                    os.environ['NO_COLOR'] = original_no_color
                if original_python_no_color is None:
                    os.environ.pop('PYTHON_ARGCOMPLETE_NO_COLOR', None)
                else:
                    os.environ['PYTHON_ARGCOMPLETE_NO_COLOR'] = original_python_no_color
        except (OSError, ValueError, AttributeError, TypeError):
            # 如果 argparse 失败，使用简单解析器
            args = parse_args_simple()
    else:
        # 直接使用简单解析器（更安全）
        args = parse_args_simple()
    
    # 显示帮助信息
    if args.help or (not args.url and not args.file):
        print_banner()
        print_help()
        return
    
    # 打印横幅
    if not args.quiet:
        print_banner()
    
    # 准备URL列表
    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(line)
        except FileNotFoundError:
            safe_print(f"{Fore.RED}错误: 文件 '{args.file}' 未找到")
            return
    
    if not urls:
        safe_print(f"{Fore.RED}错误: 未指定要扫描的URL")
        return
    
    # 准备扫描选项
    scan_options = {
        'timeout': args.timeout,
        'concurrency': args.concurrency,
        'user_agent': args.user_agent,
        'proxy': args.proxy,
        'cookies': args.cookie,
        'headers': args.header,
        'skip_checks': args.skip_checks.split(',') if args.skip_checks else [],
        'only_checks': args.only_checks.split(',') if args.only_checks else [],
        'verbose': args.verbose,
        'quiet': args.quiet
    }
    
    # 创建扫描器
    scanner = WebSecurityScanner(**scan_options)
    
    # 执行扫描
    all_results = []
    start_time = time.time()
    
    for i, url in enumerate(urls):
        if len(urls) > 1 and not args.quiet:
            safe_print(f"\n{Fore.CYAN}[{i+1}/{len(urls)}] 正在扫描: {url}")
        
        try:
            results = scanner.scan(url)
            all_results.append({
                'url': url,
                'results': results,
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            
            # 显示结果
            if not args.quiet:
                scanner.print_results(results)
                
        except Exception as e:
            import traceback
            error_msg = f"{Fore.RED}扫描 {url} 时出错: {str(e)}"
            if args.verbose:
                error_msg += f"\n{Fore.YELLOW}详细错误信息:\n{traceback.format_exc()}"
            safe_print(error_msg)
            continue
    
    # 计算总扫描时间
    total_time = time.time() - start_time
    
    # 生成报告
    if all_results:
        if not args.quiet:
            safe_print(f"\n{Fore.GREEN}{'='*60}")
            safe_print(f"{Fore.GREEN}扫描完成!")
            safe_print(f"{Fore.WHITE}总扫描URL: {len(all_results)}")
            safe_print(f"{Fore.WHITE}总耗时: {total_time:.2f}秒")
            safe_print(f"{Fore.GREEN}{'='*60}")
        
        # 保存报告到文件（纯文本格式）
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    for result in all_results:
                        generator = ReportGenerator(result['results'], result['url'])
                        report_content = generator.generate_console_report()
                        f.write(report_content)
                        f.write("\n" + "="*80 + "\n\n")
                
                if not args.quiet:
                    safe_print(f"{Fore.GREEN}报告已保存到: {args.output}")
                        
            except Exception as e:
                safe_print(f"{Fore.RED}保存报告时出错: {str(e)}")
    else:
        safe_print(f"{Fore.RED}未完成任何扫描")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        safe_print(f"\n{Fore.YELLOW}扫描被用户中断")
        sys.exit(1)
    except Exception as e:
        safe_print(f"{Fore.RED}程序出错: {str(e)}")
        sys.exit(1)
