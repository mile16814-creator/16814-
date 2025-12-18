"""
HTTP安全头与会话安全检查模块
实现6个检查点：
1. 缺少CSP（Content Security Policy）
2. 缺少X-Frame-Options
3. 缺少HSTS（HTTP Strict Transport Security）
4. Cookie未设置HttpOnly
5. Cookie未设置Secure
6. Session过期时间异常
"""

import re
import requests
from typing import Dict, List
from colorama import Fore, Style

class HttpSecurityChecks:
    """HTTP安全头与会话安全检查类"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.results = []
    
    def check_csp(self, base_url: str) -> Dict:
        """检查缺少CSP（Content Security Policy）"""
        check_name = "缺少CSP"
        description = "检测是否缺少Content Security Policy安全头"
        
        try:
            response = self.session.get(base_url, timeout=10)
            headers = response.headers
            
            csp_headers = [
                'Content-Security-Policy',
                'Content-Security-Policy-Report-Only',
                'X-Content-Security-Policy',  # 旧版Firefox
                'X-WebKit-CSP'  # 旧版Chrome/Safari
            ]
            
            found_csp = []
            for header in csp_headers:
                if header in headers:
                    found_csp.append({
                        'header': header,
                        'value': headers[header][:100] + '...' if len(headers[header]) > 100 else headers[header]
                    })
            
            severity = "中危" if not found_csp else "低危"
            status = "发现" if not found_csp else "已配置"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': {
                    'csp_headers_found': found_csp,
                    'recommendation': "配置CSP可以有效防止XSS攻击，建议设置合适的CSP策略"
                } if found_csp else "未检测到CSP相关安全头",
                'recommendation': "添加Content-Security-Policy头，限制脚本、样式等资源的加载源"
            }
            
        except Exception as e:
            return {
                'name': check_name,
                'description': description,
                'severity': '未知',
                'status': '错误',
                'details': str(e),
                'recommendation': '检查网络连接或目标可达性'
            }
    
    def check_x_frame_options(self, base_url: str) -> Dict:
        """检查缺少X-Frame-Options"""
        check_name = "缺少X-Frame-Options"
        description = "检测是否缺少X-Frame-Options安全头，防止点击劫持"
        
        try:
            response = self.session.get(base_url, timeout=10)
            headers = response.headers
            
            xfo_header = 'X-Frame-Options'
            has_xfo = xfo_header in headers
            
            severity = "中危" if not has_xfo else "低危"
            status = "发现" if not has_xfo else "已配置"
            
            details = {}
            if has_xfo:
                details = {
                    'header_value': headers[xfo_header],
                    'valid_values': ['DENY', 'SAMEORIGIN', 'ALLOW-FROM uri']
                }
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': details if has_xfo else "未检测到X-Frame-Options安全头",
                'recommendation': "添加X-Frame-Options: DENY或SAMEORIGIN头，防止页面被嵌入iframe"
            }
            
        except Exception as e:
            return {
                'name': check_name,
                'description': description,
                'severity': '未知',
                'status': '错误',
                'details': str(e),
                'recommendation': '检查网络连接或目标可达性'
            }
    
    def check_hsts(self, base_url: str) -> Dict:
        """检查缺少HSTS（HTTP Strict Transport Security）"""
        check_name = "缺少HSTS"
        description = "检测是否缺少HSTS安全头，强制使用HTTPS"
        
        try:
            # 首先检查HTTPS
            if not base_url.startswith('https://'):
                return {
                    'name': check_name,
                    'description': description,
                    'severity': "低危",
                    'status': "不适用",
                    'details': "目标未使用HTTPS，HSTS仅适用于HTTPS站点",
                    'recommendation': "首先启用HTTPS，然后配置HSTS头"
                }
            
            response = self.session.get(base_url, timeout=10, verify=False)  # 临时关闭SSL验证
            headers = response.headers
            
            hsts_headers = [
                'Strict-Transport-Security',
                'HSTS'  # 非标准但有时使用
            ]
            
            found_hsts = []
            for header in hsts_headers:
                if header in headers:
                    found_hsts.append({
                        'header': header,
                        'value': headers[header]
                    })
            
            severity = "中危" if not found_hsts else "低危"
            status = "发现" if not found_hsts else "已配置"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': {
                    'hsts_headers_found': found_hsts,
                    'max_age_pattern': r'max-age=(\d+)'
                } if found_hsts else "未检测到HSTS安全头",
                'recommendation': "添加Strict-Transport-Security头，设置合适的max-age（如31536000秒）"
            }
            
        except Exception as e:
            return {
                'name': check_name,
                'description': description,
                'severity': '未知',
                'status': '错误',
                'details': str(e),
                'recommendation': '检查网络连接或目标可达性'
            }
    
    def check_cookie_httponly(self, base_url: str) -> Dict:
        """检查Cookie未设置HttpOnly属性"""
        check_name = "Cookie未设置HttpOnly"
        description = "检测Cookie是否缺少HttpOnly属性，防止XSS窃取Cookie"
        
        try:
            response = self.session.get(base_url, timeout=10)
            cookies = response.cookies
            
            insecure_cookies = []
            secure_cookies = []
            
            for cookie in cookies:
                cookie_dict = {
                    'name': cookie.name,
                    'domain': cookie.domain or 'N/A',
                    'path': cookie.path or '/'
                }
                
                # 检查HttpOnly属性
                if not hasattr(cookie, 'httponly') or not cookie.httponly:
                    insecure_cookies.append(cookie_dict)
                else:
                    secure_cookies.append(cookie_dict)
            
            severity = "中危" if insecure_cookies else "低危"
            status = "发现" if insecure_cookies else "安全"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': {
                    'insecure_cookies': insecure_cookies,
                    'secure_cookies': secure_cookies,
                    'total_cookies': len(cookies)
                },
                'recommendation': "为所有敏感Cookie设置HttpOnly属性，防止JavaScript访问"
            }
            
        except Exception as e:
            return {
                'name': check_name,
                'description': description,
                'severity': '未知',
                'status': '错误',
                'details': str(e),
                'recommendation': '检查网络连接或目标可达性'
            }
    
    def check_cookie_secure(self, base_url: str) -> Dict:
        """检查Cookie未设置Secure属性"""
        check_name = "Cookie未设置Secure"
        description = "检测Cookie是否缺少Secure属性，防止明文传输"
        
        try:
            # 对于HTTPS站点才检查Secure属性
            is_https = base_url.startswith('https://')
            
            response = self.session.get(base_url, timeout=10, verify=is_https)
            cookies = response.cookies
            
            insecure_cookies = []
            secure_cookies = []
            
            for cookie in cookies:
                cookie_dict = {
                    'name': cookie.name,
                    'domain': cookie.domain or 'N/A',
                    'path': cookie.path or '/'
                }
                
                # 对于HTTPS站点，检查Secure属性
                if is_https:
                    if not hasattr(cookie, 'secure') or not cookie.secure:
                        insecure_cookies.append(cookie_dict)
                    else:
                        secure_cookies.append(cookie_dict)
                else:
                    # HTTP站点，Secure属性不适用
                    pass
            
            if not is_https:
                severity = "低危"
                status = "不适用"
                details = "目标未使用HTTPS，Secure属性仅适用于HTTPS站点"
            else:
                severity = "中危" if insecure_cookies else "低危"
                status = "发现" if insecure_cookies else "安全"
                details = {
                    'insecure_cookies': insecure_cookies,
                    'secure_cookies': secure_cookies,
                    'total_cookies': len(cookies)
                }
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': details,
                'recommendation': "为HTTPS站点的所有Cookie设置Secure属性，防止明文传输"
            }
            
        except Exception as e:
            return {
                'name': check_name,
                'description': description,
                'severity': '未知',
                'status': '错误',
                'details': str(e),
                'recommendation': '检查网络连接或目标可达性'
            }
    
    def check_session_expiry(self, base_url: str) -> Dict:
        """检查Session过期时间异常"""
        check_name = "Session过期时间异常"
        description = "检测Session Cookie的过期时间是否设置合理"
        
        try:
            response = self.session.get(base_url, timeout=10)
            cookies = response.cookies
            
            session_cookies = []
            for cookie in cookies:
                # 识别可能的Session Cookie（通常以session、sess、PHPSESSID等命名）
                cookie_name_lower = cookie.name.lower()
                if any(keyword in cookie_name_lower for keyword in 
                       ['session', 'sess', 'token', 'auth', 'login']):
                    
                    cookie_info = {
                        'name': cookie.name,
                        'expires': str(cookie.expires) if cookie.expires else '会话Cookie',
                        'max_age': getattr(cookie, 'max-age', None),
                        'domain': cookie.domain or 'N/A',
                        'path': cookie.path or '/'
                    }
                    
                    # 分析过期时间
                    if cookie.expires:
                        # 这里可以添加更复杂的过期时间分析
                        # 例如检查是否过期时间过长（>30天）或过短（<1小时）
                        pass
                    
                    session_cookies.append(cookie_info)
            
            severity = "信息"  # 信息性检查
            status = "信息"  # 改为标准状态
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': {
                    'session_cookies_found': session_cookies,
                    'total_cookies': len(cookies),
                    'analysis': "检查Session Cookie的过期时间设置是否合理（建议：普通用户15-30分钟，记住登录状态7-30天）"
                },
                'recommendation': "合理设置Session过期时间，平衡安全性和用户体验"
            }
            
        except Exception as e:
            return {
                'name': check_name,
                'description': description,
                'severity': '未知',
                'status': '错误',
                'details': str(e),
                'recommendation': '检查网络连接或目标可达性'
            }
    
    def get_checks(self):
        """获取所有检查点"""
        return [
            {'id': 'http_001', 'name': '缺少CSP', 'category': 'HTTP安全'},
            {'id': 'http_002', 'name': '缺少X-Frame-Options', 'category': 'HTTP安全'},
            {'id': 'http_003', 'name': '缺少HSTS', 'category': 'HTTP安全'},
            {'id': 'http_004', 'name': 'Cookie缺少HttpOnly', 'category': 'HTTP安全'},
            {'id': 'http_005', 'name': 'Cookie缺少Secure', 'category': 'HTTP安全'},
            {'id': 'http_006', 'name': '会话过期时间', 'category': 'HTTP安全'}
        ]
    
    def run_check(self, url, check_id, options):
        """运行指定检查"""
        checks = {
            'http_001': self.check_csp,
            'http_002': self.check_x_frame_options,
            'http_003': self.check_hsts,
            'http_004': self.check_cookie_httponly,
            'http_005': self.check_cookie_secure,
            'http_006': self.check_session_expiry
        }
        
        if check_id in checks:
            try:
                result = checks[check_id](url)
                status_map = {'发现': 'vulnerable', '未发现': 'safe', '安全': 'safe', '已配置': 'safe', '错误': 'error', '不适用': 'info', '信息': 'info'}
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
        """运行所有HTTP安全检查"""
        print(f"{Fore.CYAN}[*] 开始HTTP安全头与会话安全检查...{Style.RESET_ALL}")
        
        checks = [
            self.check_csp,
            self.check_x_frame_options,
            self.check_hsts,
            self.check_cookie_httponly,
            self.check_cookie_secure,
            self.check_session_expiry
        ]
        
        results = []
        for check_func in checks:
            try:
                result = check_func(base_url)
                results.append(result)
                
                # 显示进度
                if result['status'] == '发现':
                    status_color = Fore.RED
                elif result['status'] == '安全' or result['status'] == '已配置':
                    status_color = Fore.GREEN
                elif result['status'] == '不适用':
                    status_color = Fore.YELLOW
                else:
                    status_color = Fore.WHITE
                    
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
__all__ = ['HttpSecurityChecks']
