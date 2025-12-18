#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告生成模块
用于生成中文安全扫描报告
"""

import datetime
import sys
import os
from typing import Dict, Any
from colorama import Fore, Style, init

# 设置控制台编码为UTF-8（解决Windows中文乱码问题）
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 初始化colorama
init(autoreset=True)


class ReportGenerator:
    """报告生成器类"""
    
    def __init__(self, scan_results: Dict[str, Any], target_url: str):
        """
        初始化报告生成器
        
        Args:
            scan_results: 扫描结果字典
            target_url: 目标URL
        """
        self.scan_results = scan_results
        self.target_url = target_url
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 检查点分类映射
        self.check_categories = {
            "web_vulns": "一、Web漏洞",
            "config_errors": "二、配置错误/信息泄露", 
            "http_security": "三、HTTP/会话安全",
            "api_security": "四、API安全漏洞",
            "basic_exposure": "五、基础暴露面/轻量扫描"
        }
        
        # 检查点名称映射（中文）
        self.check_names = {
            # Web漏洞
            "reflected_xss": "反射型XSS",
            "stored_xss": "存储型XSS",
            "dom_xss": "DOM XSS",
            "csrf_risk": "CSRF风险",
            "url_param_unfiltered": "URL参数未过滤",
            "form_input_unvalidated": "表单输入未校验",
            
            # 配置错误/信息泄露
            "env_file_exposed": ".env文件暴露",
            "git_svn_exposed": ".git/.svn暴露",
            "backup_file_leak": "备份文件泄露",
            "directory_listing": "目录列表开启",
            "debug_mode": "Debug/开发模式开启",
            "error_info_leak": "错误信息泄露",
            
            # HTTP/会话安全
            "missing_csp": "缺少CSP",
            "missing_x_frame_options": "缺少X-Frame-Options",
            "missing_hsts": "缺少HSTS",
            "cookie_no_httponly": "Cookie未设置HttpOnly",
            "cookie_no_secure": "Cookie未设置Secure",
            "session_expiry_abnormal": "Session过期时间异常",
            
            # API安全漏洞
            "api_no_auth": "API未鉴权即可访问",
            "token_missing_returns_data": "Token缺失仍返回数据",
            "param_validation_missing": "参数校验缺失",
            "excessive_fields_returned": "返回字段过多",
            "id_param_no_auth_check": "ID参数未做权限校验",
            
            # 基础暴露面/轻量扫描
            "ip_open_ports": "IP/开放端口",
            "web_service_fingerprint": "Web服务指纹",
            "service_banner_leak": "服务Banner信息泄露",
            "https_not_forced": "HTTPS未强制",
            "mixed_content": "混合内容"
        }
        
        # 风险等级映射
        self.risk_levels = {
            "critical": "高危",
            "high": "高危",
            "medium": "中危",
            "low": "低危",
            "info": "信息"
        }
    
    def generate_console_report(self) -> str:
        """生成控制台报告"""
        report_lines = []
        
        # 报告头部
        report_lines.append(Fore.CYAN + "=" * 80)
        report_lines.append(Fore.CYAN + "                    Web安全扫描报告")
        report_lines.append(Fore.CYAN + "=" * 80)
        report_lines.append(f"目标URL: {Fore.YELLOW}{self.target_url}")
        report_lines.append(f"扫描时间: {Fore.YELLOW}{self.timestamp}")
        report_lines.append(f"扫描时长: {Fore.YELLOW}{self.scan_results.get('scan_duration', 'N/A')}秒")
        report_lines.append(Fore.CYAN + "-" * 80)
        
        # 统计信息
        total_checks = self.scan_results.get('total_checks', 0)
        vulnerabilities_found = self.scan_results.get('vulnerabilities_found', 0)
        
        report_lines.append(f"检查点总数: {Fore.YELLOW}{total_checks}")
        report_lines.append(f"发现漏洞数: {Fore.RED if vulnerabilities_found > 0 else Fore.GREEN}{vulnerabilities_found}")
        report_lines.append(Fore.CYAN + "-" * 80)
        
        # 按分类显示结果
        for category_key, category_name in self.check_categories.items():
            category_results = self.scan_results.get(category_key, {})
            if not category_results:
                continue
                
            report_lines.append(f"\n{Fore.MAGENTA}{category_name}")
            report_lines.append(Fore.MAGENTA + "-" * 60)
            
            for check_key, check_result in category_results.items():
                if check_key == 'summary':
                    continue
                    
                check_name = self.check_names.get(check_key, check_key)
                status = check_result.get('status', 'unknown')
                risk_level = check_result.get('risk_level', 'info')
                description = check_result.get('description', '')
                recommendation = check_result.get('recommendation', '')
                
                # 根据状态设置颜色
                if status == 'vulnerable':
                    status_color = Fore.RED
                    status_text = "存在风险"
                elif status == 'safe':
                    status_color = Fore.GREEN
                    status_text = "安全"
                else:
                    status_color = Fore.YELLOW
                    status_text = "未检测"
                
                # 风险等级颜色
                risk_color = Fore.RED if risk_level in ['critical', 'high'] else \
                            Fore.YELLOW if risk_level == 'medium' else \
                            Fore.BLUE if risk_level == 'low' else Fore.WHITE
                
                report_lines.append(f"  {Fore.WHITE}✓ {check_name}:")
                report_lines.append(f"    状态: {status_color}{status_text}")
                report_lines.append(f"    风险等级: {risk_color}{self.risk_levels.get(risk_level, risk_level)}")
                
                if description:
                    report_lines.append(f"    描述: {Fore.WHITE}{description}")
                if recommendation and status == 'vulnerable':
                    report_lines.append(f"    建议: {Fore.GREEN}{recommendation}")
                
                report_lines.append("")
        
        # 总结部分
        report_lines.append(Fore.CYAN + "=" * 80)
        report_lines.append(Fore.CYAN + "                        扫描总结")
        report_lines.append(Fore.CYAN + "-" * 80)
        
        # 按风险等级统计
        risk_stats = self._calculate_risk_statistics()
        for risk_level, count in risk_stats.items():
            if count > 0:
                risk_name = self.risk_levels.get(risk_level, risk_level)
                color = Fore.RED if risk_level in ['critical', 'high'] else \
                       Fore.YELLOW if risk_level == 'medium' else \
                       Fore.BLUE if risk_level == 'low' else Fore.WHITE
                report_lines.append(f"{risk_name}: {color}{count}个")
        
        # 总体建议
        if vulnerabilities_found > 0:
            report_lines.append(f"\n{Fore.RED}⚠️  安全警告: 发现{vulnerabilities_found}个安全风险，建议立即修复！")
            report_lines.append(f"{Fore.YELLOW}建议:")
            report_lines.append(f"{Fore.YELLOW}1. 优先修复高危和中危漏洞")
            report_lines.append(f"{Fore.YELLOW}2. 定期进行安全扫描")
            report_lines.append(f"{Fore.YELLOW}3. 实施安全开发流程")
        else:
            report_lines.append(f"\n{Fore.GREEN}✅ 恭喜！未发现安全漏洞。")
            report_lines.append(f"{Fore.YELLOW}建议:")
            report_lines.append(f"{Fore.YELLOW}1. 继续保持良好的安全实践")
            report_lines.append(f"{Fore.YELLOW}2. 定期更新系统和组件")
            report_lines.append(f"{Fore.YELLOW}3. 实施持续安全监控")
        
        report_lines.append(Fore.CYAN + "=" * 80)
        
        return "\n".join(report_lines)
    
    def save_text_report(self, output_path: str) -> bool:
        """保存文本报告到文件"""
        try:
            report_content = self.generate_console_report()
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            return True
            
        except Exception as e:
            print(f"{Fore.RED}保存文本报告失败: {e}")
            return False
    
    def _calculate_risk_statistics(self) -> Dict[str, int]:
        """计算风险统计"""
        stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for category_key in self.check_categories.keys():
            category_results = self.scan_results.get(category_key, {})
            for check_key, check_result in category_results.items():
                if check_key == 'summary':
                    continue
                    
                if check_result.get('status') == 'vulnerable':
                    risk_level = check_result.get('risk_level', 'info')
                    if risk_level in stats:
                        stats[risk_level] += 1
        
        return stats
