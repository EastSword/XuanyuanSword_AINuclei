import subprocess
import logging
import json
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def load_config():
    """从配置文件加载参数"""
    try:
        config_path = Path(__file__).parent / "config.json"
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error("配置文件未找到：config.json")
        raise
    except json.JSONDecodeError:
        logging.error("配置文件格式错误")
        raise

def update_nuclei():
    """带配置的更新操作"""
    try:
        config = load_config()
        
        # 动态获取二进制路径
        nuclei_binary = Path(config["paths"]["nuclei_binary"])
        if not nuclei_binary.exists():
            raise FileNotFoundError(f"Nuclei可执行文件不存在：{nuclei_binary}")
        
        # 构建命令参数
        cmd = [str(nuclei_binary.resolve()), "-update"]
        
        # 添加代理参数
        if config["proxy"]["enable"]:
            cmd.extend(["-proxy", config["proxy"]["address"]])
            logging.info("已启用代理更新")
        
        # 执行更新命令
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True  # 网页6推荐的文本模式
        )
        logging.info(f"模板更新成功\n{result.stdout}")
        
    except subprocess.CalledProcessError as e:
        error_msg = f"更新失败：{e.output if e.output else '无错误详情'}"
        logging.error(error_msg)
    except Exception as e:
        logging.error(f"未知错误：{str(e)}")

if __name__ == "__main__":
    update_nuclei()