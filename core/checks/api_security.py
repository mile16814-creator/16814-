"""
API安全漏洞检查模块
实现5个检查点：
1. API未鉴权即可访问
2. Token缺失仍返回数据
3. 参数校验缺失
4. 返回字段过多（信息越权迹象）
5. ID参数未做权限校验（只检测现象）
"""

import re
import json
import requests
from urllib.parse import urljoin
from typing import Dict, List, Optional
from colorama import Fore, Style

class ApiSecurityChecks:
    """API安全漏洞检查类"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.results = []
    
    def discover_api_endpoints(self, base_url: str) -> List[str]:
        """发现可能的API端点"""
        api_endpoints = []
        
        # 常见API路径模式
        common_api_patterns = [
            '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/users', '/products', '/orders', '/auth', '/login',
            '/admin/', '/user/', '/account/', '/profile/'
        ]
        
        # 首先检查robots.txt和sitemap.xml
        discovery_urls = [
            urljoin(base_url, 'robots.txt'),
            urljoin(base_url, 'sitemap.xml'),
            urljoin(base_url, 'sitemap_index.xml')
        ]
        
        for url in discovery_urls:
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    content = response.text
                    # 从robots.txt中提取路径
                    if 'robots.txt' in url:
                        lines = content.split('\n')
                        for line in lines:
                            if line.startswith('Disallow:') or line.startswith('Allow:'):
                                path = line.split(':')[1].strip()
                                if path and path != '/':
                                    api_endpoints.append(path)
            except:
                continue
        
        # 添加常见API路径
        for pattern in common_api_patterns:
            api_endpoints.append(pattern)
        
        return list(set(api_endpoints))  # 去重
    
    def check_api_auth_bypass(self, base_url: str) -> Dict:
        """检查API未鉴权即可访问"""
        check_name = "API未鉴权即可访问"
        description = "检测API端点是否缺少身份验证，可直接访问"
        
        try:
            # 发现可能的API端点
            endpoints = self.discover_api_endpoints(base_url)
            
            unauthorized_access = []
            tested_endpoints = []
            
            # 测试每个端点（限制数量）
            for endpoint in endpoints[:10]:  # 最多测试10个端点
                url = urljoin(base_url, endpoint)
                tested_endpoints.append(url)
                
                try:
                    # 尝试无认证访问
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        content_type = response.headers.get('Content-Type', '')
                        
                        # 检查响应内容是否看起来像API响应
                        is_api_response = False
                        if 'application/json' in content_type:
                            is_api_response = True
                        elif 'text/html' not in content_type:
                            # 尝试解析为JSON
                            try:
                                json.loads(response.text[:100])
                                is_api_response = True
                            except:
                                pass
                        
                        if is_api_response:
                            # 检查响应是否包含敏感数据
                            response_text = response.text.lower()
                            sensitive_keywords = [
                                'user', 'email', 'password', 'token',
                                'id', 'name', 'address', 'phone'
                            ]
                            
                            sensitive_count = sum(1 for keyword in sensitive_keywords 
                                                if keyword in response_text)
                            
                            if sensitive_count > 2:  # 如果包含多个敏感关键词
                                unauthorized_access.append({
                                    'endpoint': endpoint,
                                    'url': url,
                                    'status_code': response.status_code,
                                    'sensitive_keywords_found': sensitive_count,
                                    'response_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                                })
                                
                except Exception as e:
                    continue
            
            severity = "高危" if unauthorized_access else "低危"
            status = "发现" if unauthorized_access else "未发现"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': {
                    'unauthorized_endpoints': unauthorized_access,
                    'tested_endpoints': tested_endpoints,
                    'total_tested': len(tested_endpoints)
                } if unauthorized_access else f"测试了{len(tested_endpoints)}个端点，未发现未鉴权的API访问",
                'recommendation': "为所有API端点添加身份验证机制，使用JWT、OAuth或API密钥等认证方式"
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
    
    def check_token_missing_data_leak(self, base_url: str) -> Dict:
        """检查Token缺失仍返回数据"""
        check_name = "Token缺失仍返回数据"
        description = "检测API在缺少认证Token时是否仍返回敏感数据"
        
        try:
            # 寻找可能需要认证的端点
            auth_endpoints = [
                '/api/user', '/api/profile', '/api/account',
                '/api/admin', '/api/settings', '/api/me'
            ]
            
            data_leaks = []
            
            for endpoint in auth_endpoints:
                url = urljoin(base_url, endpoint)
                
                try:
                    # 第一次请求：不带任何认证头
                    response1 = self.session.get(url, timeout=5)
                    
                    if response1.status_code == 200:
                        # 尝试添加一个假的认证头
                        headers = {'Authorization': 'Bearer fake_token_12345'}
                        response2 = self.session.get(url, headers=headers, timeout=5)
                        
                        # 比较两次响应
                        if response1.text == response2.text:
                            # 响应相同，可能认证无效或不需要认证
                            try:
                                data1 = json.loads(response1.text)
                                # 检查是否包含敏感字段
                                sensitive_fields = ['id', 'username', 'email', 'name']
                                found_sensitive = any(field in data1 for field in sensitive_fields)
                                
                                if found_sensitive:
                                    data_leaks.append({
                                        'endpoint': endpoint,
                                        'url': url,
                                        'status_code': response1.status_code,
                                        'response_same_without_token': True,
                                        'sensitive_fields_found': [f for f in sensitive_fields if f in data1]
                                    })
                            except json.JSONDecodeError:
                                # 不是JSON响应，跳过
                                pass
                                
                except Exception as e:
                    continue
            
            severity = "高危" if data_leaks else "低危"
            status = "发现" if data_leaks else "未发现"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': data_leaks if data_leaks else "未发现Token缺失时的数据泄露",
                'recommendation': "实现严格的Token验证，无效或缺失Token时应返回401未授权错误，而不是敏感数据"
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
    
    def check_parameter_validation(self, base_url: str) -> Dict:
        """检查参数校验缺失"""
        check_name = "参数校验缺失"
        description = "检测API参数是否缺少输入验证"
        
        try:
            # 测试常见参数注入
            test_cases = [
                {
                    'param': 'id',
                    'values': ["1", "' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd"]
                },
                {
                    'param': 'page',
                    'values': ["1", "-1", "1000000", "1; DROP TABLE users"]
                },
                {
                    'param': 'limit',
                    'values': ["10", "0", "-1", "1000000", "10; SELECT * FROM users"]
                }
            ]
            
            validation_issues = []
            
            # 首先获取一个正常的API响应作为基准
            test_url = urljoin(base_url, '/api/test')  # 假设的测试端点
            try:
                normal_response = self.session.get(test_url, timeout=5)
                if normal_response.status_code != 200:
                    # 尝试其他常见端点
                    for endpoint in ['/api/users', '/api/products', '/api/data']:
                        test_url = urljoin(base_url, endpoint)
                        normal_response = self.session.get(test_url, timeout=5)
                        if normal_response.status_code == 200:
                            break
            except:
                normal_response = None
            
            # 如果找到了可用的API端点，进行参数测试
            if normal_response and normal_response.status_code == 200:
                base_url_for_test = test_url
                
                for test_case in test_cases:
                    param = test_case['param']
                    
                    for value in test_case['values']:
                        test_params = {param: value}
                        
                        try:
                            response = self.session.get(base_url_for_test, params=test_params, timeout=5)
                            
                            if response.status_code == 200:
                                # 检查响应是否与正常响应不同
                                if normal_response.text != response.text:
                                    # 尝试检测可能的注入成功迹象
                                    response_text = response.text.lower()
                                    
                                    # SQL注入迹象
                                    sql_indicators = ['sql', 'syntax', 'database', 'mysql', 'postgresql']
                                    # XSS迹象
                                    xss_indicators = ['script', 'alert', 'onerror', 'onload']
                                    # 路径遍历迹象
                                    path_indicators = ['etc/passwd', 'root:', 'bin/']
                                    
                                    issue_type = None
                                    if any(indicator in response_text for indicator in sql_indicators):
                                        issue_type = '可能的SQL注入'
                                    elif any(indicator in response_text for indicator in xss_indicators):
                                        issue_type = '可能的XSS'
                                    elif any(indicator in response_text for indicator in path_indicators):
                                        issue_type = '可能的路径遍历'
                                    else:
                                        issue_type = '参数验证问题'
                                    
                                    validation_issues.append({
                                        'parameter': param,
                                        'malicious_value': value,
                                        'issue_type': issue_type,
                                        'status_code': response.status_code,
                                        'response_differs': True
                                    })
                                    break  # 发现一个问题就停止这个参数的测试
                                    
                        except Exception as e:
                            continue
            
            severity = "中危" if validation_issues else "低危"
            status = "发现" if validation_issues else "未发现"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': validation_issues if validation_issues else "未发现明显的参数验证问题",
                'recommendation': "对所有API参数进行严格的输入验证，包括类型、范围、长度、格式等检查"
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
    
    def check_excessive_data_exposure(self, base_url: str) -> Dict:
        """检查返回字段过多（信息越权迹象）"""
        check_name = "返回字段过多（信息越权迹象）"
        description = "检测API是否返回过多敏感字段，可能存在信息越权"
        
        try:
            # 测试常见用户相关端点
            user_endpoints = ['/api/user', '/api/profile', '/api/account', '/api/me']
            
            excessive_fields_cases = []
            
            for endpoint in user_endpoints:
                url = urljoin(base_url, endpoint)
                
                try:
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        try:
                            data = json.loads(response.text)
                            
                            if isinstance(data, dict):
                                # 定义敏感字段类别
                                highly_sensitive = ['password', 'token', 'secret', 'private_key', 'ssn']
                                sensitive = ['email', 'phone', 'address', 'birth_date', 'credit_card']
                                normal = ['name', 'username', 'id', 'created_at', 'updated_at']
                                
                                all_fields = list(data.keys())
                                found_highly_sensitive = [f for f in all_fields if any(hs in f.lower() for hs in highly_sensitive)]
                                found_sensitive = [f for f in all_fields if any(s in f.lower() for s in sensitive)]
                                found_normal = [f for f in all_fields if any(n in f.lower() for n in normal)]
                                
                                total_fields = len(all_fields)
                                
                                # 如果发现高度敏感字段或字段总数过多
                                if found_highly_sensitive or total_fields > 15:
                                    excessive_fields_cases.append({
                                        'endpoint': endpoint,
                                        'url': url,
                                        'total_fields': total_fields,
                                        'highly_sensitive_fields': found_highly_sensitive,
                                        'sensitive_fields': found_sensitive,
                                        'normal_fields': found_normal,
                                        'all_fields': all_fields
                                    })
                                    
                        except json.JSONDecodeError:
                            # 不是JSON响应，跳过
                            continue
                            
                except Exception as e:
                    continue
            
            severity = "中危" if excessive_fields_cases else "低危"
            status = "发现" if excessive_fields_cases else "未发现"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': excessive_fields_cases if excessive_fields_cases else "未发现明显的字段过多问题",
                'recommendation': "遵循最小权限原则，只返回必要的字段，使用DTO（数据传输对象）过滤敏感信息"
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
    
    def check_idor(self, base_url: str) -> Dict:
        """检查ID参数未做权限校验（IDOR）"""
        check_name = "ID参数未做权限校验"
        description = "检测ID参数是否缺少权限校验，可能存在越权访问"
        
        try:
            # 测试常见的ID参数端点模式
            id_patterns = [
                '/api/user/{id}',
                '/api/order/{id}',
                '/api/document/{id}',
                '/api/file/{id}'
            ]
            
            idor_indicators = []
            
            # 由于我们不知道具体的ID值，只能检测模式
            # 首先尝试发现包含ID参数的端点
            discovery_urls = [
                urljoin(base_url, 'api/users/1'),
                urljoin(base_url, 'api/orders/100'),
                urljoin(base_url, 'api/products/1')
            ]
            
            for url in discovery_urls:
                try:
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        # 检查响应是否包含用户数据
                        try:
                            data = json.loads(response.text)
                            if isinstance(data, dict):
                                # 检查是否包含用户标识字段
                                user_identifiers = ['user_id', 'owner_id', 'author_id', 'creator_id']
                                found_identifiers = [field for field in user_identifiers if field in data]
                                
                                if found_identifiers:
                                    # 尝试访问其他ID（IDOR测试）
                                    # 例如，如果访问了 /api/users/1，尝试访问 /api/users/2
                                    url_parts = url.rstrip('/').split('/')
                                    if len(url_parts) >= 2:
                                        current_id = url_parts[-1]
                                        if current_id.isdigit():
                                            next_id = str(int(current_id) + 1)
                                            next_url = '/'.join(url_parts[:-1] + [next_id])
                                            
                                            try:
                                                next_response = self.session.get(next_url, timeout=5)
                                                if next_response.status_code == 200:
                                                    # 两个不同的ID都能访问，可能存在IDOR
                                                    idor_indicators.append({
                                                        'tested_url': url,
                                                        'next_url': next_url,
                                                        'current_id': current_id,
                                                        'next_id': next_id,
                                                        'both_accessible': True,
                                                        'note': '需要进一步验证是否为同一用户的数据'
                                                    })
                                            except:
                                                pass
                                            
                        except json.JSONDecodeError:
                            continue
                            
                except Exception as e:
                    continue
            
            severity = "高危" if idor_indicators else "低危"
            status = "发现迹象" if idor_indicators else "未发现"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': idor_indicators if idor_indicators else "未发现明显的IDOR迹象（需要具体ID值进行测试）",
                'recommendation': "对所有资源访问进行权限校验，确保用户只能访问自己有权限的资源，使用会话上下文验证资源所有权"
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
            {'id': 'api_001', 'name': 'API认证绕过', 'category': 'API安全'},
            {'id': 'api_002', 'name': 'Token缺失/数据泄露', 'category': 'API安全'},
            {'id': 'api_003', 'name': '参数验证不足', 'category': 'API安全'},
            {'id': 'api_004', 'name': '过度数据暴露', 'category': 'API安全'},
            {'id': 'api_005', 'name': 'IDOR漏洞', 'category': 'API安全'}
        ]
    
    def run_check(self, url, check_id, options):
        """运行指定检查"""
        checks = {
            'api_001': self.check_api_auth_bypass,
            'api_002': self.check_token_missing_data_leak,
            'api_003': self.check_parameter_validation,
            'api_004': self.check_excessive_data_exposure,
            'api_005': self.check_idor
        }
        
        if check_id in checks:
            try:
                result = checks[check_id](url)
                status_map = {'发现': 'vulnerable', '发现迹象': 'suspicious', '未发现': 'safe', '安全': 'safe', '错误': 'error', '不适用': 'info', '信息': 'info'}
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
        """运行所有API安全检查"""
        print(f"{Fore.CYAN}[*] 开始API安全漏洞检查...{Style.RESET_ALL}")
        
        checks = [
            self.check_api_auth_bypass,
            self.check_token_missing_data_leak,
            self.check_parameter_validation,
            self.check_excessive_data_exposure,
            self.check_idor
        ]
        
        results = []
        for check_func in checks:
            try:
                result = check_func(base_url)
                results.append(result)
                
                # 显示进度
                if result['status'] == '发现' or result['status'] == '发现迹象':
                    status_color = Fore.RED
                elif result['status'] == '未发现':
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
__all__ = ['ApiSecurityChecks']
