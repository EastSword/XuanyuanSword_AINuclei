import json
import subprocess
import argparse
import sys
from pathlib import Path
from datetime import datetime

# 固定路径配置
NUCLEI_BINARY = Path(__file__).parent / 'nuclei_darwin_arm64'
CONFIG_FILE = Path(__file__).parent / 'config.json'

def validate_files():
    """验证必要文件存在性"""
    if not NUCLEI_BINARY.exists():
        raise FileNotFoundError(f"Nuclei可执行文件未找到: {NUCLEI_BINARY}")
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(f"配置文件未找到: {CONFIG_FILE}")

def load_config():
    """加载并验证配置文件"""
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
    
    # 强制校验配置结构
    if 'proxy' not in config:
        config['proxy'] = {'enable': False}
    elif config['proxy']['enable'] and 'address' not in config['proxy']:
        raise ValueError("启用代理时必须配置address字段")
    
    return config


def execute_scan(cmd):
    """执行扫描进程并实时输出日志"""
    log_path = Path(__file__).parent / f"scan_{datetime.now().strftime('%Y%m%d%H%M')}.log"
    
    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        ) as proc, log_path.open('w') as log_file:
            
            print(f"[*] 扫描日志保存至: {log_path}")
            
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break
                if line:
                    print(line.strip())
                    log_file.write(line)
                    
            return proc.returncode
                    
    except KeyboardInterrupt:
        print("\n[!] 用户终止扫描")
        return 1

def build_command(config, target_file, pocs):
    """构建Nuclei命令行参数（添加POC指定功能）"""
    cmd = [
        './'+str(NUCLEI_BINARY),
        '-list', str(target_file),
        '-rate-limit', '100',
        '-timeout', '30'
    ]
    
    # 添加POC路径参数
    if pocs:
        validated_pocs = []
        for poc_path in pocs:
            path = Path(poc_path).resolve()
            if not path.exists():
                raise FileNotFoundError(f"POC路径不存在: {path}")
            validated_pocs.append(str(path))
        cmd.extend(['-t', ','.join(validated_pocs)])  # 支持多POC目录
    
    # 代理配置保持不变
    if config['proxy'].get('enable', "True"):
        cmd.extend(['-proxy', config['proxy']['address']])
    
    print(cmd)

    return cmd

if __name__ == '__main__':
    try:
        # 修改参数解析部分
        parser = argparse.ArgumentParser(description='Nuclei自动化扫描脚本')
        parser.add_argument('-t', '--target', required=True, help='目标文件路径')
        parser.add_argument('-p', '--poc', nargs='+',  # 支持多个POC路径
                          help='指定POC模板路径（文件或目录）')
        args = parser.parse_args()
        
        # 前置验证
        validate_files()
        config = load_config()
        
        # 目标文件验证
        target_path = Path(args.target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"目标文件不存在: {target_path}")
            
        # 构建命令
        cmd = build_command(config, target_path, args.poc)
        print(f"[*] 执行命令: {' '.join(cmd)}")
        
        # 启动扫描
        exit_code = execute_scan(cmd)
        sys.exit(exit_code)
        
    except Exception as e:
        print(f"[!] 致命错误: {str(e)}")
        sys.exit(1)