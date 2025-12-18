#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web漏洞检查模块
包含6个检查点：
1. 反射型XSS
2. 存储型XSS（只检测展示）
3. DOM XSS（前端风险点）
4. CSRF风险（缺少Token）
5. URL参数未过滤
6. 表单输入未校验
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode

class WebVulnerabilityChecks:
    """Web漏洞检查"""
    
    def __init__(self):
        self.session = requests.Session()
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '\'"><script>alert(1)</script>',
            'javascript:alert(1)',
            '"><svg/onload=alert(1)>'
        ]
        
    def get_checks(self):
        """获取所有检查点"""
        return [
            {
                'id': 'web_001',
                'name': '反射型XSS漏洞',
                'category': 'Web漏洞',
                'description': '检测URL参数中的反射型XSS漏洞'
            },
            {
                'id': 'web_002',
                'name': '存储型XSS风险点',
                'category': 'Web漏洞',
                'description': '检测可能存储XSS的表单提交点'
            },
            {
                'id': 'web_003',
                'name': 'DOM XSS风险点',
                'category': 'Web漏洞',
                'description': '检测前端JavaScript中的DOM XSS风险'
            },
            {
                'id': 'web_004',
                'name': 'CSRF风险（缺少Token）',
                'category': 'Web漏洞',
                'description': '检测表单是否缺少CSRF Token防护'
            },
            {
                'id': 'web_005',
                'name': 'URL参数未过滤',
                'category': 'Web漏洞',
                'description': '检测URL参数是否直接输出到页面'
            },
            {
                'id': 'web_006',
                'name': '表单输入未校验',
                'category': 'Web漏洞',
                'description': '检测表单是否缺少输入验证'
            }
        ]
    
    def run_check(self, url, check_id, options):
        """运行指定检查"""
        checks = {
            'web_001': self.check_reflected_xss,
            'web_002': self.check_stored_xss,
            'web_003': self.check_dom_xss,
            'web_004': self.check_csrf,
            'web_005': self.check_url_parameter_filtering,
            'web_006': self.check_form_validation
        }
        
        if check_id in checks:
            return checks[check_id](url, options)
        else:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'未知检查ID: {check_id}',
                'details': {},
                'recommendation': '请检查检查ID是否正确'
            }
    
    def check_reflected_xss(self, url, options):
        """检查反射型XSS漏洞"""
        try:
            # 解析URL获取参数
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': 'URL中没有查询参数，无法测试反射型XSS',
                    'details': {'url': url},
                    'recommendation': '无需修复'
                }
            
            # 测试每个参数
            vulnerable_params = []
            test_details = []
            
            for param_name in params:
                for payload in self.xss_payloads[:2]:  # 只测试前2个payload
                    # 构造测试URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    # 发送请求
                    headers = {'User-Agent': options.get('user_agent', '')}
                    response = self.session.get(
                        test_url,
                        timeout=options.get('timeout', 10),
                        headers=headers
                    )
                    
                    # 检查响应中是否包含payload
                    if payload in response.text:
                        vulnerable_params.append(param_name)
                        test_details.append({
                            'parameter': param_name,
                            'payload': payload,
                            'response_contains': True
                        })
                        break
            
            if vulnerable_params:
                return {
                    'status': 'vulnerable',
                    'severity': 'high',
                    'description': f'发现反射型XSS漏洞，受影响参数: {", ".join(vulnerable_params)}',
                    'details': {
                        'vulnerable_parameters': vulnerable_params,
                        'tests': test_details,
                        'url': url
                    },
                    'recommendation': '对用户输入进行HTML编码过滤，使用安全的输出函数'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未发现反射型XSS漏洞',
                    'details': {'tested_parameters': list(params.keys()), 'url': url},
                    'recommendation': '继续保持良好的输入过滤实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查反射型XSS时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_stored_xss(self, url, options):
        """检查存储型XSS风险点"""
        try:
            # 获取页面内容
            headers = {'User-Agent': options.get('user_agent', '')}
            response = self.session.get(
                url,
                timeout=options.get('timeout', 10),
                headers=headers
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找表单
            forms = soup.find_all('form')
            form_details = []
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                form_inputs = form.find_all('input')
                
                input_names = []
                for inp in form_inputs:
                    input_type = inp.get('type', 'text')
                    input_name = inp.get('name', '')
                    if input_name and input_type in ['text', 'textarea', 'search', 'email', 'password']:
                        input_names.append(input_name)
                
                if input_names:
                    form_details.append({
                        'action': form_action,
                        'method': form_method,
                        'inputs': input_names,
                        'has_csrf_token': self._has_csrf_token(form)
                    })
            
            if form_details:
                return {
                    'status': 'suspicious',
                    'severity': 'medium',
                    'description': f'发现{len(form_details)}个表单提交点，可能存在存储型XSS风险',
                    'details': {
                        'forms': form_details,
                        'url': url
                    },
                    'recommendation': '对表单输入进行严格验证和过滤，对输出进行编码'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未发现表单提交点',
                    'details': {'url': url},
                    'recommendation': '无需修复'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查存储型XSS时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_dom_xss(self, url, options):
        """检查DOM XSS风险点"""
        try:
            # 获取页面内容
            headers = {'User-Agent': options.get('user_agent', '')}
            response = self.session.get(
                url,
                timeout=options.get('timeout', 10),
                headers=headers
            )
            
            # 查找JavaScript代码中的风险函数
            risk_patterns = [
                r'\.innerHTML\s*=',
                r'\.outerHTML\s*=',
                r'document\.write\(',
                r'eval\(',
                r'setTimeout\(',
                r'setInterval\(',
                r'\.src\s*=',
                r'location\.',
                r'window\.location'
            ]
            
            risk_matches = []
            for pattern in risk_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    # 获取上下文
                    start = max(0, match.start() - 50)
                    end = min(len(response.text), match.end() + 50)
                    context = response.text[start:end]
                    
                    risk_matches.append({
                        'pattern': pattern,
                        'context': context.strip()
                    })
            
            if risk_matches:
                return {
                    'status': 'suspicious',
                    'severity': 'medium',
                    'description': f'发现{len(risk_matches)}个DOM操作风险点',
                    'details': {
                        'risk_points': risk_matches[:5],  # 只显示前5个
                        'url': url
                    },
                    'recommendation': '避免使用innerHTML等不安全DOM操作，使用textContent代替'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未发现明显的DOM XSS风险点',
                    'details': {'url': url},
                    'recommendation': '继续保持良好的前端安全实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查DOM XSS时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_csrf(self, url, options):
        """检查CSRF风险"""
        try:
            # 获取页面内容
            headers = {'User-Agent': options.get('user_agent', '')}
            response = self.session.get(
                url,
                timeout=options.get('timeout', 10),
                headers=headers
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找表单
            forms = soup.find_all('form')
            forms_without_token = []
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # 只检查POST方法
                if form_method == 'post':
                    if not self._has_csrf_token(form):
                        forms_without_token.append({
                            'action': form_action,
                            'method': form_method
                        })
            
            if forms_without_token:
                return {
                    'status': 'vulnerable',
                    'severity': 'medium',
                    'description': f'发现{len(forms_without_token)}个POST表单缺少CSRF Token',
                    'details': {
                        'forms': forms_without_token,
                        'url': url
                    },
                    'recommendation': '为所有POST表单添加CSRF Token防护'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未发现缺少CSRF Token的POST表单',
                    'details': {'url': url},
                    'recommendation': '继续保持良好的CSRF防护实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查CSRF风险时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_url_parameter_filtering(self, url, options):
        """检查URL参数过滤"""
        try:
            # 解析URL获取参数
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': 'URL中没有查询参数',
                    'details': {'url': url},
                    'recommendation': '无需修复'
                }
            
            # 获取原始页面
            headers = {'User-Agent': options.get('user_agent', '')}
            original_response = self.session.get(
                url,
                timeout=options.get('timeout', 10),
                headers=headers
            )
            
            # 测试参数是否直接输出
            test_param = 'test_xss_param_123'
            test_value = f'TEST_VALUE_{test_param}'
            
            test_params = params.copy()
            test_params[test_param] = [test_value]
            test_query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            test_response = self.session.get(
                test_url,
                timeout=options.get('timeout', 10),
                headers=headers
            )
            
            # 检查测试值是否出现在响应中
            if test_value in test_response.text:
                return {
                    'status': 'suspicious',
                    'severity': 'low',
                    'description': 'URL参数可能未经过滤直接输出到页面',
                    'details': {
                        'test_parameter': test_param,
                        'test_value': test_value,
                        'found_in_response': True,
                        'url': url
                    },
                    'recommendation': '对所有用户输入进行过滤和编码后再输出'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': 'URL参数似乎经过过滤处理',
                    'details': {'url': url},
                    'recommendation': '继续保持良好的输入过滤实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查URL参数过滤时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_form_validation(self, url, options):
        """检查表单输入验证"""
        try:
            # 获取页面内容
            headers = {'User-Agent': options.get('user_agent', '')}
            response = self.session.get(
                url,
                timeout=options.get('timeout', 10),
                headers=headers
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找表单
            forms = soup.find_all('form')
            forms_without_validation = []
            
            for form in forms:
                form_inputs = form.find_all('input')
                has_validation = False
                
                # 检查是否有验证属性
                for inp in form_inputs:
                    if inp.get('required') or inp.get('pattern') or inp.get('minlength') or inp.get('maxlength'):
                        has_validation = True
                        break
                
                # 检查是否有JavaScript验证
                form_html = str(form)
                if 'onSubmit=' in form_html or 'onsubmit=' in form_html:
                    has_validation = True
                
                if not has_validation and form_inputs:
                    forms_without_validation.append({
                        'action': form.get('action', ''),
                        'method': form.get('method', 'get'),
                        'input_count': len(form_inputs)
                    })
            
            if forms_without_validation:
                return {
                    'status': 'suspicious',
                    'severity': 'low',
                    'description': f'发现{len(forms_without_validation)}个表单可能缺少输入验证',
                    'details': {
                        'forms': forms_without_validation,
                        'url': url
                    },
                    'recommendation': '为表单添加客户端和服务器端输入验证'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '表单似乎有基本的输入验证',
                    'details': {'url': url},
                    'recommendation': '继续保持良好的输入验证实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查表单输入验证时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def _has_csrf_token(self, form):
        """检查表单是否有CSRF Token"""
        csrf_patterns = ['csrf', 'token', '_token', 'authenticity_token']
        
        # 检查隐藏输入
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        for inp in hidden_inputs:
            input_name = inp.get('name', '').lower()
            input_value = inp.get('value', '')
            
            for pattern in csrf_patterns:
                if pattern in input_name or (len(input_value) > 20 and 'csrf' in input_name):
                    return True
        
        return False
