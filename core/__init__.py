"""
Web安全扫描工具核心模块
包含扫描引擎和检查模块
"""

__version__ = '1.0.0'
__author__ = 'Mile16814'

from .scanner import WebSecurityScanner
from .checks import (
    web_vulns,
    config_errors,
    http_security,
    api_security,
    basic_exposure
)
