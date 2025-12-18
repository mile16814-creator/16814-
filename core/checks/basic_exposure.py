"""
基础暴露面与轻量扫描检查模块
实现5个检查点：
1. IP，开放端口
2. Web服务指纹
3. 服务Banner信息泄露
4. HTTPS未强制
5. 混合内容（HTTP资源）
"""

import re
import socket
import requests
import ssl
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple
from colorama import Fore, Style

class BasicExposureChecks:
    """基础暴露面与轻量扫描检查类"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.results = []
    
    def check_open_ports(self, base_url: str) -> Dict:
        """检查IP和开放端口"""
        check_name = "IP与开放端口"
        description = "检测目标主机的常见开放端口"
        
        try:
            # 解析URL获取主机名
            parsed_url = urlparse(base_url)
            hostname = parsed_url.hostname
            
            if not hostname:
                return {
                    'name': check_name,
                    'description': description,
                    'severity': '低危',
                    'status': '跳过',
                    'details': '无法解析URL中的主机名',
                    'recommendation': '检查URL格式是否正确'
                }
            
            # 解析主机名为IP地址
            ip_addresses = []
            try:
                # 首先检查是否是有效的IPv4地址
                try:
                    socket.inet_aton(hostname)
                    ip_addresses.append(hostname)
                except socket.error:
                    # 不是IPv4，尝试IPv6
                    try:
                        socket.inet_pton(socket.AF_INET6, hostname)
                        ip_addresses.append(hostname)
                    except (socket.error, AttributeError):
                        # 不是IP地址，尝试DNS解析
                        try:
                            # 获取IPv4地址
                            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
                            for addr in addr_info:
                                ip = addr[4][0]
                                if ip not in ip_addresses:
                                    ip_addresses.append(ip)
                        except socket.gaierror:
                            # DNS解析失败
                            pass
            except Exception as e:
                # 解析过程中出现其他错误
                pass
            
            # 如果无法解析IP地址，仍然尝试使用主机名进行端口扫描
            if not ip_addresses:
                # 记录警告，但继续执行
                pass
            
            # 如果没有解析到IP，使用主机名进行端口扫描
            scan_target = ip_addresses[0] if ip_addresses else hostname
            
            # 常见Web相关端口
            common_ports = [
                (80, 'HTTP'),
                (443, 'HTTPS'),
                (8080, 'HTTP-Alt'),
                (8443, 'HTTPS-Alt'),
                (3000, 'Node.js'),
                (5000, 'Flask/Django'),
                (8000, 'Python HTTP'),
                (9000, 'PHP-FPM'),
                (3306, 'MySQL'),
                (5432, 'PostgreSQL'),
                (27017, 'MongoDB'),
                (6379, 'Redis'),
                (11211, 'Memcached'),
                (21, 'FTP'),
                (22, 'SSH'),
                (25, 'SMTP'),
                (53, 'DNS')
            ]
            
            open_ports = []
            
            # 检测是否是云服务（如Heroku），这些服务可能对所有端口返回连接成功
            is_cloud_service = any(keyword in hostname.lower() for keyword in [
                'herokuapp.com', 'appspot.com', 'azurewebsites.net', 
                'cloudapp.net', 'amazonaws.com', 'cloudfront.net'
            ])
            
            for port, service in common_ports[:10]:  # 限制检查数量
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)  # 设置较短的超时时间
                    
                    # 尝试连接
                    result = sock.connect_ex((scan_target, port))
                    
                    if result == 0:
                        # 连接成功，需要进一步验证
                        verified = False
                        port_status = '可能开放'
                        
                        try:
                            # 对于HTTP端口，尝试发送请求验证
                            if port in [80, 8080, 8000]:
                                sock.settimeout(2)
                                try:
                                    sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + hostname.encode() + b'\r\nConnection: close\r\n\r\n')
                                    response = sock.recv(512)
                                    if response and b'HTTP' in response:
                                        verified = True
                                        port_status = '开放'
                                except:
                                    # 发送/接收失败，但连接已建立
                                    if is_cloud_service:
                                        # 云服务可能只开放80/443，其他端口即使连接成功也可能不可用
                                        if port not in [80, 443]:
                                            if sock:
                                                try:
                                                    sock.close()
                                                except:
                                                    pass
                                            continue  # 跳过非标准端口
                                    verified = False
                            elif port in [443, 8443]:
                                # HTTPS端口，尝试SSL握手
                                try:
                                    context = ssl.create_default_context()
                                    context.check_hostname = False
                                    context.verify_mode = ssl.CERT_NONE
                                    ssock = context.wrap_socket(sock, server_hostname=hostname)
                                    ssock.close()
                                    verified = True
                                    port_status = '开放'
                                except:
                                    # SSL握手失败，但TCP连接成功
                                    if is_cloud_service and port == 443:
                                        verified = True  # 云服务443端口通常可用
                                    else:
                                        # SSL握手失败，不能确定端口真正开放
                                        verified = False
                            else:
                                # 其他端口（数据库、SSH等），需要更严格的验证
                                # 对于云服务，这些端口通常不开放，即使连接成功
                                if is_cloud_service:
                                    # 云服务的非标准端口即使连接成功也通常不可用
                                    if sock:
                                        try:
                                            sock.close()
                                        except:
                                            pass
                                    continue
                                
                                # 对于非云服务，尝试验证端口
                                # 重要：不能仅因为连接成功就认为端口开放
                                # 某些防火墙/代理会接受连接但端口实际未开放
                                try:
                                    # 尝试发送一些探测数据，看是否有响应或连接被关闭
                                    sock.settimeout(1)
                                    try:
                                        # 尝试发送少量数据，看连接是否保持
                                        # 对于大多数服务，即使不响应也会保持连接
                                        sock.send(b'\n')
                                        # 尝试读取响应，但不使用MSG_PEEK（Windows兼容性）
                                        sock.settimeout(0.3)
                                        try:
                                            data = sock.recv(1)
                                            # 如果能读取到数据，说明端口真正开放
                                            if data:
                                                verified = True
                                                port_status = '开放'
                                            else:
                                                # 连接被关闭，端口可能不开放
                                                verified = False
                                        except socket.timeout:
                                            # 读取超时：连接保持但无数据
                                            # 关键问题：某些网络环境（特别是代理/防火墙）可能会接受所有TCP连接
                                            # 即使端口实际未开放。因此，仅凭连接成功不能证明端口开放。
                                            #
                                            # 采用最保守的策略：对于读取超时的情况，除非我们能收到实际数据响应，
                                            # 否则不标记为已验证的开放端口。
                                            #
                                            # 注意：这可能导致某些真正开放但需要客户端先发送命令的端口（如SSH）被遗漏，
                                            # 但这比误报要好。如需准确检测，请使用专业的端口扫描工具（如nmap）。
                                            verified = False
                                            port_status = '可能开放（未验证）'
                                        except (socket.error, OSError, ConnectionResetError, BrokenPipeError):
                                            # 连接被关闭，端口不开放
                                            verified = False
                                    except (socket.error, OSError, BrokenPipeError):
                                        # 发送失败，连接可能已关闭
                                        verified = False
                                except Exception:
                                    # 验证过程中出错，保守处理：不认为端口开放
                                    verified = False
                        except Exception:
                            verified = False
                        
                        # 只报告验证过的端口，或云服务的标准端口
                        if verified:
                            open_ports.append({
                                'port': port,
                                'service': service,
                                'status': port_status,
                                'verified': True
                            })
                        elif is_cloud_service and port in [80, 443]:
                            # 云服务的标准端口（80/443），即使未完全验证也报告
                            open_ports.append({
                                'port': port,
                                'service': service,
                                'status': '开放',
                                'verified': True
                            })
                        # 其他情况不报告（端口可能不真正开放）
                    
                    if sock:
                        try:
                            sock.close()
                        except:
                            pass
                except socket.timeout:
                    # 连接超时，端口不开放
                    continue
                except socket.gaierror:
                    # DNS解析失败，跳过
                    if sock:
                        try:
                            sock.close()
                        except:
                            pass
                    continue
                except Exception:
                    # 其他错误，跳过
                    if sock:
                        try:
                            sock.close()
                        except:
                            pass
                    continue
            
            severity = "信息"  # 端口扫描通常为信息级别
            status = "信息"  # 改为标准状态
            
            # 添加说明信息
            note = '仅扫描了常见端口，非全面端口扫描'
            if is_cloud_service:
                note += '；检测到云服务，仅报告已验证的标准端口（80/443）'
            if open_ports:
                verified_count = sum(1 for p in open_ports if p.get('verified', False))
                note += f'；发现 {len(open_ports)} 个开放端口（{verified_count} 个已验证）'
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': {
                    'hostname': hostname,
                    'ip_addresses': ip_addresses if ip_addresses else ['无法解析'],
                    'primary_ip': ip_addresses[0] if ip_addresses else None,
                    'open_ports': open_ports,
                    'total_ports_scanned': len(common_ports[:10]),
                    'note': note
                },
                'recommendation': "关闭不必要的端口，仅开放业务必需的端口，使用防火墙限制访问"
            }
            
        except Exception as e:
            return {
                'name': check_name,
                'description': description,
                'severity': '未知',
                'status': '错误',
                'details': str(e),
                'recommendation': '检查网络连接或DNS解析'
            }
    
    def check_web_fingerprint(self, base_url: str) -> Dict:
        """检查Web服务指纹"""
        check_name = "Web服务指纹"
        description = "识别Web服务器、框架、CMS等技术栈"
        
        try:
            response = self.session.get(base_url, timeout=10)
            
            fingerprints = {
                'server': '未知',
                'framework': '未知',
                'cms': '未知',
                'programming_language': '未知'
            }
            
            # 检查Server头
            server_header = response.headers.get('Server', '')
            if server_header:
                fingerprints['server'] = server_header
            
            # 检查X-Powered-By头
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                fingerprints['framework'] = powered_by
            
            # 检查响应内容中的技术特征
            content = response.text.lower()
            
            # Web服务器识别
            server_patterns = [
                (r'nginx[/\s](\d+\.\d+\.\d+)', 'Nginx'),
                (r'apache[/\s](\d+\.\d+\.\d+)', 'Apache'),
                (r'microsoft-iis[/\s](\d+\.\d+)', 'IIS'),
                (r'cloudflare', 'Cloudflare'),
                (r'cloudfront', 'AWS CloudFront')
            ]
            
            for pattern, server in server_patterns:
                match = re.search(pattern, server_header.lower())
                if match:
                    fingerprints['server'] = f"{server} {match.group(1)}"
                    break
            
            # 框架识别
            framework_indicators = [
                ('wordpress', 'WordPress'),
                ('drupal', 'Drupal'),
                ('joomla', 'Joomla'),
                ('laravel', 'Laravel'),
                ('django', 'Django'),
                ('flask', 'Flask'),
                ('express', 'Express.js'),
                ('react', 'React'),
                ('vue', 'Vue.js'),
                ('angular', 'Angular'),
                ('spring', 'Spring'),
                ('ruby on rails', 'Ruby on Rails'),
                ('asp.net', 'ASP.NET'),
                ('php', 'PHP'),
                ('node.js', 'Node.js'),
                ('python', 'Python'),
                ('java', 'Java'),
                (r'wp-', 'WordPress'),  # WordPress特定路径
                (r'/wp-content/', 'WordPress'),
                (r'/wp-admin/', 'WordPress'),
                (r'/media/jui/', 'Joomla'),
                (r'/sites/default/', 'Drupal')
            ]
            
            for indicator, framework in framework_indicators:
                if re.search(indicator, content) or (indicator in server_header.lower()) or (indicator in powered_by.lower()):
                    if fingerprints['framework'] == '未知':
                        fingerprints['framework'] = framework
                    elif framework not in fingerprints['framework']:
                        fingerprints['framework'] += f", {framework}"
            
            # CMS识别
            cms_indicators = [
                ('wordpress', 'WordPress'),
                ('drupal', 'Drupal'),
                ('joomla', 'Joomla'),
                ('magento', 'Magento'),
                ('shopify', 'Shopify'),
                ('wix', 'Wix'),
                ('squarespace', 'Squarespace')
            ]
            
            for indicator, cms in cms_indicators:
                if indicator in content:
                    fingerprints['cms'] = cms
                    break
            
            severity = "信息"
            status = "信息"  # 改为标准状态
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': fingerprints,
                'recommendation': "考虑隐藏或修改服务器标识信息，减少攻击面"
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
    
    def check_banner_info_leak(self, base_url: str) -> Dict:
        """检查服务Banner信息泄露"""
        check_name = "服务Banner信息泄露"
        description = "检测服务是否泄露详细的版本和配置信息"
        
        try:
            response = self.session.get(base_url, timeout=10)
            headers = response.headers
            
            info_leaks = []
            
            # 检查可能泄露信息的响应头
            sensitive_headers = [
                'Server',
                'X-Powered-By',
                'X-AspNet-Version',
                'X-AspNetMvc-Version',
                'X-Runtime',
                'X-Version',
                'X-Generator'
            ]
            
            for header in sensitive_headers:
                if header in headers:
                    value = headers[header]
                    # 检查是否包含版本号等详细信息
                    if re.search(r'\d+\.\d+', value):
                        info_leaks.append({
                            'header': header,
                            'value': value,
                            'risk': '版本信息泄露'
                        })
            
            # 检查HTML中的注释和元标签
            content = response.text
            
            # 查找HTML注释中的技术信息
            comment_pattern = r'<!--(.*?)-->'
            comments = re.findall(comment_pattern, content, re.DOTALL)
            
            for comment in comments[:5]:  # 只检查前5个注释
                comment_lower = comment.lower()
                tech_keywords = ['version', 'build', 'generated', 'created by', 'powered by']
                
                if any(keyword in comment_lower for keyword in tech_keywords):
                    info_leaks.append({
                        'source': 'HTML注释',
                        'content': comment[:100] + '...' if len(comment) > 100 else comment,
                        'risk': '技术信息泄露'
                    })
            
            # 检查JavaScript文件中的信息
            js_pattern = r'<script[^>]*src=["\']([^"\']+\.js)["\'][^>]*>'
            js_files = re.findall(js_pattern, content, re.IGNORECASE)
            
            for js_file in js_files[:3]:  # 只检查前3个JS文件
                js_url = urljoin(base_url, js_file)
                try:
                    js_response = self.session.get(js_url, timeout=5)
                    if js_response.status_code == 200:
                        js_content = js_response.text[:500]  # 只检查前500字符
                        
                        # 检查JS中的版本信息
                        version_patterns = [
                            r'version\s*[:=]\s*["\'](\d+\.\d+\.\d+)["\']',
                            r'v\d+\.\d+\.\d+',
                            r'@version\s+\d+\.\d+'
                        ]
                        
                        for pattern in version_patterns:
                            match = re.search(pattern, js_content)
                            if match:
                                info_leaks.append({
                                    'source': f'JavaScript文件: {js_file}',
                                    'content': f'发现版本信息: {match.group()}',
                                    'risk': '版本信息泄露'
                                })
                                break
                except:
                    continue
            
            severity = "低危" if info_leaks else "信息"
            status = "发现" if info_leaks else "未发现"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': info_leaks if info_leaks else "未发现明显的Banner信息泄露",
                'recommendation': "移除或模糊化响应头中的版本信息，清理HTML注释中的技术细节"
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
    
    def check_https_enforcement(self, base_url: str) -> Dict:
        """检查HTTPS未强制"""
        check_name = "HTTPS未强制"
        description = "检测网站是否强制使用HTTPS，防止HTTP访问"
        
        try:
            parsed_url = urlparse(base_url)
            
            # 如果已经是HTTPS，检查是否可以从HTTP访问
            if parsed_url.scheme == 'https':
                http_url = base_url.replace('https://', 'http://')
                
                try:
                    response = self.session.get(http_url, timeout=5, allow_redirects=False)
                    
                    if response.status_code == 200:
                        # HTTP可以直接访问，没有重定向到HTTPS
                        severity = "中危"
                        status = "发现"
                        details = "HTTP可以直接访问，未重定向到HTTPS"
                    elif 300 <= response.status_code < 400:
                        # 有重定向
                        location = response.headers.get('Location', '')
                        if location.startswith('https://'):
                            severity = "低危"
                            status = "已重定向"
                            details = f"HTTP重定向到HTTPS: {location}"
                        else:
                            severity = "中危"
                            status = "发现"
                            details = f"HTTP重定向到非HTTPS: {location}"
                    else:
                        severity = "低危"
                        status = "安全"
                        details = "HTTP访问被拒绝或返回错误"
                        
                except:
                    severity = "低危"
                    status = "安全"
                    details = "HTTP访问失败"
                    
            else:
                # 原始URL是HTTP，检查是否有HTTPS版本
                https_url = base_url.replace('http://', 'https://')
                
                try:
                    response = self.session.get(https_url, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        severity = "中危"
                        status = "发现"
                        details = "网站支持HTTPS但未默认使用，建议强制HTTPS"
                    else:
                        severity = "高危"
                        status = "发现"
                        details = "网站未启用HTTPS，所有通信均为明文"
                        
                except:
                    severity = "高危"
                    status = "发现"
                    details = "HTTPS不可用或证书错误"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': details,
                'recommendation': "配置服务器强制所有流量使用HTTPS，设置HSTS头，将HTTP请求重定向到HTTPS"
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
    
    def check_mixed_content(self, base_url: str) -> Dict:
        """检查混合内容（HTTP资源）"""
        check_name = "混合内容（HTTP资源）"
        description = "检测HTTPS页面中是否引用了HTTP资源，导致安全警告"
        
        try:
            # 只对HTTPS页面检查混合内容
            if not base_url.startswith('https://'):
                return {
                    'name': check_name,
                    'description': description,
                    'severity': '低危',
                    'status': '不适用',
                    'details': '目标页面未使用HTTPS，混合内容检查不适用',
                    'recommendation': '首先启用HTTPS，然后检查混合内容问题'
                }
            
            response = self.session.get(base_url, timeout=10, verify=False)
            content = response.text
            
            # 查找HTTP资源引用
            http_patterns = [
                (r'src=["\']http://([^"\']+)["\']', '脚本/图片/iframe源'),
                (r'href=["\']http://([^"\']+)["\']', '链接'),
                (r'url\(["\']?http://([^"\')]+)["\']?\)', 'CSS背景图'),
                (r'@import\s+["\']http://([^"\']+)["\']', 'CSS导入'),
                (r'action=["\']http://([^"\']+)["\']', '表单提交')
            ]
            
            mixed_content = []
            
            for pattern, resource_type in http_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    full_url = f"http://{match}"
                    mixed_content.append({
                        'resource_type': resource_type,
                        'url': full_url,
                        'risk': '混合内容'
                    })
            
            severity = "中危" if mixed_content else "低危"
            status = "发现" if mixed_content else "未发现"
            
            return {
                'name': check_name,
                'description': description,
                'severity': severity,
                'status': status,
                'details': {
                    'mixed_content_found': mixed_content,
                    'total_resources': len(mixed_content),
                    'note': '混合内容会导致浏览器安全警告，降低用户体验和安全性'
                } if mixed_content else "未发现混合内容",
                'recommendation': "将所有资源引用改为HTTPS或使用协议相对URL（//example.com/resource）"
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
            {'id': 'basic_001', 'name': 'IP与开放端口', 'category': '基础暴露面'},
            {'id': 'basic_002', 'name': 'Web服务指纹', 'category': '基础暴露面'},
            {'id': 'basic_003', 'name': '服务Banner信息泄露', 'category': '基础暴露面'},
            {'id': 'basic_004', 'name': 'HTTPS未强制', 'category': '基础暴露面'},
            {'id': 'basic_005', 'name': '混合内容（HTTP资源）', 'category': '基础暴露面'}
        ]
    
    def run_check(self, url, check_id, options):
        """运行指定检查"""
        checks = {
            'basic_001': self.check_open_ports,
            'basic_002': self.check_web_fingerprint,
            'basic_003': self.check_banner_info_leak,
            'basic_004': self.check_https_enforcement,
            'basic_005': self.check_mixed_content
        }
        
        if check_id in checks:
            try:
                result = checks[check_id](url)
                status_map = {'发现': 'vulnerable', '未发现': 'safe', '安全': 'safe', '错误': 'error', '不适用': 'info', '跳过': 'info', '信息': 'info'}
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
        """运行所有基础暴露面检查"""
        print(f"{Fore.CYAN}[*] 开始基础暴露面与轻量扫描检查...{Style.RESET_ALL}")
        
        checks = [
            self.check_open_ports,
            self.check_web_fingerprint,
            self.check_banner_info_leak,
            self.check_https_enforcement,
            self.check_mixed_content
        ]
        
        results = []
        for check_func in checks:
            try:
                result = check_func(base_url)
                results.append(result)
                
                # 显示进度
                if result['status'] == '发现':
                    status_color = Fore.RED
                elif result['status'] == '安全' or result['status'] == '未发现':
                    status_color = Fore.GREEN
                elif result['status'] == '不适用' or result['status'] == '跳过':
                    status_color = Fore.YELLOW
                else:
                    status_color = Fore.WHITE
                    
                print(f"  {status_color}[{result['status'][0]}]{Style.RESET_ALL} {result['name']} - {result['severity']}")
                
            except Exception as e:
                print(f"  {Fore.RED}[E]{Style.RESET_ALL} 检查执行失败: {str(e)[:50]}...")
        
        print(f"{Fore.CYAN}[*] 基础暴露面与轻量扫描检查完成，共{len(results)}项检查{Style.RESET_ALL}")
        return results
