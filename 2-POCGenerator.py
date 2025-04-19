import json
import re
import logging
import requests
import yaml
from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup
from openai import OpenAI

class ConfigManager:
    @staticmethod
    def load():
        """安全加载并验证配置文件"""
        config_path = Path(__file__).parent / "config.json"
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # 验证必要配置项
            required = {
                'api_settings': ['deepseek_api_key', 'vuln_article_url'],
                'paths': ['template_dir']
            }
            for section, keys in required.items():
                if not config.get(section):
                    raise ValueError(f"Missing config section: {section}")
                for key in keys:
                    if key not in config[section]:
                        raise ValueError(f"Missing {section}.{key} in config")
            
            return config
        except FileNotFoundError:
            raise RuntimeError("config.json not found")
        except json.JSONDecodeError:
            raise RuntimeError("Invalid JSON format in config")

class NucleiPOCGenerator:
    def __init__(self):
        self.config = ConfigManager.load()
        self._init_components()
        self._validate_paths()

    def _init_components(self):
        """初始化各组件"""
        # 初始化OpenAI客户端
        self.client = OpenAI(
            api_key=self.config['api_settings']['deepseek_api_key'],
            base_url="https://api.deepseek.com",
            timeout=30
        )
        
        # 配置HTTP会话
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) NucleiPOC/2.1',
            'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'
        })
        
        # 配置日志
        self.logger = logging.getLogger('NucleiPOCGenerator')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def _validate_paths(self):
        """验证路径配置"""
        template_dir = Path(self.config['paths']['template_dir'])
        try:
            template_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Template directory ready: {template_dir.resolve()}")
        except PermissionError as e:
            raise RuntimeError(f"Permission denied: {template_dir}") from e

    def generate_poc(self):
        """主生成流程"""
        try:
            # 获取漏洞文章URL
            article_url = self.config['api_settings']['vuln_article_url']
            self.logger.info(f"Processing vulnerability article: {article_url}")
            
            # 爬取文章内容
            article_data = self._crawl_article(article_url)
            
            # AI分析生成模板参数
            poc_params = self._analyze_with_ai(article_data)
            
            # 构建Nuclei模板
            return self._build_template(poc_params)
        except Exception as e:
            self.logger.error(f"Generation failed: {str(e)}")
            return None

    def _crawl_article(self, url):
        """智能爬取漏洞文章"""
        for retry in range(3):
            try:
                resp = self.session.get(url, timeout=20)
                resp.raise_for_status()
                
                if resp.status_code == 403:
                    raise RuntimeError("Anti-bot triggered")
                
                soup = BeautifulSoup(resp.text, 'lxml')
                return {
                    'title': self._extract_title(soup),
                    'cve': self._extract_cve(soup),
                    'endpoint': self._find_vuln_path(soup),
                    'payloads': self._extract_payloads(soup),
                    'references': self._find_references(soup),
                    'raw_html': resp.text[:5000]  # Limit content size
                }
            except requests.RequestException as e:
                if retry == 2:
                    raise RuntimeError(f"Request failed after 3 attempts: {str(e)}")
                self.logger.warning(f"Retrying ({retry+1}/3)...")

    def _analyze_with_ai(self, content):
        """使用AI分析生成模板参数"""
        prompt = self._build_prompt(content)
        
        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": "严格使用JSON格式输出"},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,
                    max_tokens=2000,
                    response_format={"type": "json_object"}
                )
                return self._process_ai_response(response.choices[0].message.content)
            except Exception as e:
                if attempt == 2:
                    raise RuntimeError(f"API request failed: {str(e)}")
                self.logger.warning(f"Retrying API call ({attempt+1}/3)...")

    def _build_prompt(self, content):
        """构建AI提示模板"""
        return f"""根据漏洞报告生成Nuclei模板（JSON格式）：

输入特征：
- 漏洞路径：{content['endpoint']}
- 有效载荷：
{chr(10).join(f'- {p}' for p in content['payloads'][:2])}
- 参考链接：
{chr(10).join(content['references'][:2])}

输出要求：
1. 严重等级按CVSS评分划分
2. 必须包含{{{{BaseURL}}}}变量
3. 包含状态码、关键词、正则匹配

输出格式：
{{
  "id": "漏洞ID",
  "name": "漏洞名称",
  "method": "HTTP方法",
  "paths": ["攻击路径"],
  "matchers": {{
    "status": 200,
    "keywords": ["特征关键词"],
    "regex": ["正则表达式"] 
  }},
  "severity": "严重等级",
  "references": ["参考链接"],
  "description": "漏洞描述",
  "fofa_query": "FOFA查询语句",
  "tags": ["漏洞类型"]
}}"""

    def _process_ai_response(self, response_text):
        """处理AI响应"""
        try:
            data = json.loads(response_text.strip('` \n'))
            # 路径处理
            if 'paths' in data:
                data['paths'] = [f"{{{{BaseURL}}}}{p}" for p in data['paths']]
            # 必要字段验证
            required_fields = ['id', 'method', 'matchers']
            for field in required_fields:
                if field not in data:
                    raise ValueError(f"Missing required field: {field}")
            return data
        except Exception as e:
            self.logger.error(f"Invalid AI response: {str(e)}")
            raise

    def _build_template(self, ai_data):
        """构建Nuclei模板文件"""
        template = {
            "id": ai_data.get("id", "auto-generated"),
            "info": {
                "name": ai_data.get("name", "Unknown Vulnerability"),
                "author": "AutoPOCGenerator",
                "severity": ai_data.get("severity", "medium"),
                "description": ai_data.get("description", "Generated by DeepSeek AI"),
                "reference": ai_data.get("references", []),
                "tags": ai_data.get("tags", ["ai-generated"]),
                "metadata": {
                    "fofa-query": ai_data.get("fofa_query", "")
                }
            },
            "requests": [{
                "method": ai_data.get("method", "GET"),
                "path": ai_data.get("paths", ["{{BaseURL}}"]),
                "matchers-condition": "and",
                "matchers": [
                    {"type": "status", "status": [ai_data["matchers"]["status"]]},
                    {"type": "word", "words": ai_data["matchers"]["keywords"]}
                ]
            }]
        }

        # 添加正则匹配
        if ai_data["matchers"].get("regex"):
            template["requests"][0]["matchers"].append({
                "type": "regex", 
                "regex": ai_data["matchers"]["regex"]
            })

        # 生成文件名
        template_dir = Path(self.config['paths']['template_dir'])
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = template_dir / f"{template['id']}_{timestamp}.yaml"

        # 写入文件
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(template, f, allow_unicode=True, sort_keys=False)
        
        self.logger.info(f"Template saved: {filename}")
        return str(filename.resolve())

    # Helper methods
    def _extract_title(self, soup):
        title = soup.find('h1')
        return title.text.strip() if title else "Untitled Vulnerability"

    def _extract_cve(self, soup):
        match = re.search(r'CVE-\d{4}-\d+', soup.text)
        return match.group() if match else None

    def _find_vuln_path(self, soup):
        for code in soup.find_all('code'):
            text = code.text.strip()
            if re.search(r'(/+api|/+admin|\.\./)', text):
                return re.sub(r'https?://[^/]+', '{{BaseURL}}', text)
        return "/vulnerable_endpoint"

    def _extract_payloads(self, soup):
        return [pre.text for pre in soup.find_all('pre') 
                if any(kw in pre.text.lower() for kw in ['poc', 'exploit', 'curl'])]

    def _find_references(self, soup):
        return list({
            a['href'] for a in soup.find_all('a', href=True)
            if any(kw in a['href'] for kw in ['cve', 'advisory', 'security'])
        })[:3]

if __name__ == "__main__":
    try:
        generator = NucleiPOCGenerator()
        result = generator.generate_poc()
        print(f"Generated POC: {result}")
    except Exception as e:
        print(f"Initialization failed: {str(e)}")