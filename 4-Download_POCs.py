#!/usr/bin/env python3
import os
import json
import asyncio
import hashlib
import yaml
import shutil
import requests
import subprocess
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

CONFIG_FILE = "config.json"
REPO_FILE = "repo.csv"
CLONE_DIR = "clone-templates"
POC_DIR = "poc"
TMP_DIR = ".tmp"
NUCLEI_BIN = "./nuclei_darwin_arm64"
MAX_WORKERS = 20
TIMEOUT = 21600

class NucleiEnterpriseManager:
    def __init__(self):
        self.config = self._load_config()
        self._init_git_config()
        self._init_workspace()
        self.github_token = self.config.get('GITHUB_TOKEN')

    def _init_workspace(self):
        """初始化工作目录结构"""
        os.makedirs(CLONE_DIR, exist_ok=True)
        os.makedirs(POC_DIR, exist_ok=True)
        shutil.rmtree(TMP_DIR, ignore_errors=True)
        os.makedirs(TMP_DIR, exist_ok=True)

    def _load_config(self):
        """加载配置文件"""
        try:
            with open(CONFIG_FILE) as f:
                config = json.load(f)
                config.setdefault('ENABLE_STAGE1', True)
                config.setdefault('GIT_PARALLEL', 8)
                config.setdefault('GIT_DEPTH', 1)
                return config
        except Exception as e:
            raise RuntimeError(f"配置加载失败: {str(e)}")

    def _init_git_config(self):
        """配置Git优化参数"""
        os.system(f"git config --global core.compression 0")
        os.system(f"git config --global core.parallelClone true")
        os.system(f"git config --global pack.threads {self.config['GIT_PARALLEL']}")

    async def _async_git_ops(self, url):
        """异步Git操作"""
        repo_name = url.split('/')[-1].replace('.git', '')
        target_dir = os.path.join(CLONE_DIR, repo_name.lower())
        
        async def run_command(cmd):
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            return await proc.wait()

        for retry in range(3):
            try:
                if os.path.exists(target_dir):
                    return_code = await run_command([
                        "git", "-C", target_dir, "pull",
                        "--depth", str(self.config['GIT_DEPTH']),
                        "--filter=tree:0"
                    ])
                else:
                    return_code = await run_command([
                        "git", "clone",
                        "--depth", str(self.config['GIT_DEPTH']),
                        "--filter=tree:0",
                        url, target_dir
                    ])
                
                if return_code == 0:
                    return
                await asyncio.sleep(2 ** retry)
            except Exception as e:
                print(f"Git操作异常: {str(e)}")

    async def dynamic_repo_discovery(self):
        """动态仓库同步"""
        if not self.config['ENABLE_STAGE1']:
            print(f"\n{'='*30} 已跳过仓库同步阶段 {'='*30}")
            return

        print(f"\n{'='*30} 阶段1: 动态仓库同步 {'='*30}")
        new_repos = await self._fetch_github_repos()
        self._update_repo_registry(new_repos)
        
        with open(REPO_FILE) as f:
            urls = {line.strip() for line in f if line.strip()}
        
        tasks = [self._async_git_ops(url) for url in urls]
        batch_size = self.config['GIT_PARALLEL'] * 2
        for i in range(0, len(tasks), batch_size):
            await asyncio.gather(*tasks[i:i+batch_size])

    async def _fetch_github_repos(self):
        """获取GitHub仓库"""
        headers = {
            "Authorization": f"token {self.github_token}",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        try:
            response = requests.get(
                "https://api.github.com/search/repositories",
                params={
                    "q": "nuclei in:name,description,topics",
                    "sort": "updated",
                    "order": "desc",
                    "per_page": 100
                },
                headers=headers,
                timeout=30
            )
            #print(response.json().get('items', []))
            return [
                repo['clone_url'] for repo in response.json().get('items', [])
                if (datetime.now() - datetime.strptime(repo['updated_at'], "%Y-%m-%dT%H:%M:%SZ")) < timedelta(days=30)
            ]
        except Exception as e:
            print(f"GitHub API请求失败: {str(e)}")
            return []

    def _update_repo_registry(self, new_repos):
        """更新仓库清单"""
        existing = set()
        if os.path.exists(REPO_FILE):
            with open(REPO_FILE, 'r') as f: 
                existing = {line.strip() for line in f}
        with open(REPO_FILE, 'w') as f:
            f.write("\n".join(existing.union(set(new_repos))))

    def enterprise_deduplication(self):
        """跨仓库去重"""
        print(f"\n{'='*30} 阶段2: 智能去重 {'='*30}")
        hash_registry = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for root, _, files in os.walk(CLONE_DIR):
                for file in files:
                    if file.endswith(('.yml', '.yaml')):
                        path = os.path.join(root, file)
                        futures.append(executor.submit(self._calculate_sha256, path))
            for future in as_completed(futures):
                path, file_hash = future.result()
                if file_hash in hash_registry: 
                    os.remove(path)
                else: 
                    hash_registry[file_hash] = path

    def dynamic_categorization(self):
        """动态分类"""
        print(f"\n{'='*30} 阶段3: 智能分类 {'='*30}")
        existing_hashes = {
            self._calculate_sha256(os.path.join(root, file))[1] 
            for root, _, files in os.walk(POC_DIR) 
            for file in files
        }
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(self._process_poc, root, file, existing_hashes)
                for root, _, files in os.walk(CLONE_DIR)
                for file in files 
                if file.endswith(('.yml', '.yaml'))
            ]
            completed = 0
            total = len(futures)
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    print(f"处理进度: {completed}/{total} ({completed/total:.1%})")

    def _process_poc(self, root, file, existing_hashes):
        """处理单个POC文件"""
        src = os.path.join(root, file)
        _, file_hash = self._calculate_sha256(src)
        if file_hash in existing_hashes: 
            return
        try:
            with open(src, 'r') as f:
                tags = yaml.safe_load(f).get('info', {}).get('tags', [])
            with ThreadPoolExecutor(max_workers=8) as io_executor:
                for tag in tags:
                    dest_dir = os.path.join(TMP_DIR, tag.lower())
                    os.makedirs(dest_dir, exist_ok=True)
                    io_executor.submit(shutil.copy, src, os.path.join(dest_dir, file))
        except Exception as e:
            pass

    def enterprise_validation(self):
        """有效性校验"""
        print(f"\n{'='*30} 阶段4: 有效性校验 {'='*30}")
        file_paths = []
        for root, _, files in os.walk(TMP_DIR):
            file_paths.extend(os.path.join(root, f) for f in files)
        batch_size = 200
        for i in range(0, len(file_paths), batch_size):
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                list(executor.map(self._validate_poc, file_paths[i:i+batch_size]))
        self._migrate_valid_files()

    def _validate_poc(self, path):
        """Nuclei验证"""
        try:
            result = subprocess.run(
                [NUCLEI_BIN, "-validate", "-t", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120
            )
            if result.returncode != 0:
                os.remove(path)
        except Exception:
            os.remove(path)

    def _migrate_valid_files(self):
        """迁移有效文件"""
        with ThreadPoolExecutor(max_workers=8) as executor:
            for root, _, files in os.walk(TMP_DIR):
                for file in files:
                    src = os.path.join(root, file)
                    dest = os.path.join(POC_DIR, os.path.relpath(src, TMP_DIR))
                    executor.submit(self._safe_move, src, dest)

    def _safe_move(self, src, dest):
        """安全移动文件"""
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.move(src, dest)

    def _calculate_sha256(self, path):
        """计算文件哈希"""
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return (path, hasher.hexdigest())

    def generate_index(self):
        """生成索引文件"""
        with open('poc.txt', 'w') as f:
            for root, _, files in os.walk(POC_DIR):
                for file in files:
                    if file.endswith(('.yml', '.yaml')):
                        f.write(f"{os.path.relpath(os.path.join(root, file), POC_DIR)}\n")

if __name__ == "__main__":
    manager = NucleiEnterpriseManager()
    try:
        asyncio.run(manager.dynamic_repo_discovery())
        manager.enterprise_deduplication()
        manager.dynamic_categorization()
        manager.enterprise_validation()
        manager.generate_index()
        total = sum(len(files) for _, _, files in os.walk(POC_DIR))
        print(f"\n有效POC总数: {total}")
    except KeyboardInterrupt:
        shutil.rmtree(TMP_DIR, ignore_errors=True)
        exit(1)