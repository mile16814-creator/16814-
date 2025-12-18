@echo off
chcp 65001 > nul
echo ========================================
echo    Web安全扫描工具 - 依赖安装
echo ========================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到Python，请先安装Python 3.8+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [信息] 检测到Python环境
python --version

echo.
echo [信息] 正在安装依赖包...
echo.

REM 安装依赖
pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo [错误] 依赖安装失败，请检查网络连接
    pause
    exit /b 1
)

echo.
echo [成功] 所有依赖已安装完成！
echo.
echo 使用方法:
echo   1. 运行 scan.bat 启动扫描
echo   2. 或使用命令: python scanner.py [URL]
echo.
pause
