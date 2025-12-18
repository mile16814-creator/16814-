@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
echo ========================================
echo    Web安全扫描工具 - 启动扫描
echo ========================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到Python，请先安装Python 3.8+
    echo 请先运行 install.bat 安装依赖
    pause
    exit /b 1
)

echo [信息] 检测到Python环境
python --version

REM 检查是否有参数
if "%1"=="" (
    echo [交互模式] 请输入要扫描的URL:
    set /p target_url=URL: 
    if "!target_url!"=="" (
        echo [错误] 未输入URL
        pause
        exit /b 1
    )
    echo.
    echo [信息] 开始扫描: !target_url!
    echo.
    python scanner.py "!target_url!"
) else (
    echo [信息] 开始扫描...
    echo.
    python scanner.py %*
)

echo.
if errorlevel 1 (
    echo [错误] 扫描过程中出现错误
) else (
    echo [完成] 扫描任务已完成
)

echo.
pause
