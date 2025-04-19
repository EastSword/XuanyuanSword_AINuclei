import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import subprocess
from pathlib import Path

CONFIG_PATH = "config.json"
SCRIPT_MAP = {
    1: "1-Update_nuel.py",
    2: "2-POCGGenerator.py",
    3: "3-Scan.py",
    4: "4-Download_POCs.py"
}

class NucleiGUI:
    def __init__(self, master):
        self.master = master
        master.title("轩辕剑-智能漏洞扫描系统 v1.0")
        self.config = self.load_config()
        
        # 界面初始化
        self.init_ui()
        self.init_config_editor()

    def init_ui(self):
        """主操作界面"""
        main_frame = ttk.Frame(self.master, padding=20)
        main_frame.grid(row=0, column=0, sticky="nsew")

        # 功能按钮区
        ttk.Button(main_frame, text="1. 更新模板库", command=self.run_update).grid(row=0, column=0, pady=5, sticky="ew")
        ttk.Button(main_frame, text="2. POC生成器", command=self.open_poc_generator).grid(row=1, column=0, pady=5, sticky="ew")
        ttk.Button(main_frame, text="3. 启动扫描", command=self.open_scanner).grid(row=2, column=0, pady=5, sticky="ew")
        ttk.Button(main_frame, text="4. 下载POC库", command=self.run_download).grid(row=3, column=0, pady=5, sticky="ew")
        ttk.Button(main_frame, text="配置管理", command=self.show_config_editor).grid(row=4, column=0, pady=10, sticky="ew")

    def init_config_editor(self):
        """配置编辑窗口"""
        self.config_window = tk.Toplevel(self.master)
        self.config_window.withdraw()
        
        editor_frame = ttk.Frame(self.config_window, padding=20)
        editor_frame.pack(fill="both", expand=True)
        
        # 配置项表格
        self.tree = ttk.Treeview(editor_frame, columns=("value",), show="tree")
        self.tree.heading("#0", text="配置项")
        self.tree.heading("value", text="值")
        
        # 动态加载配置
        for section in self.config:
            parent = self.tree.insert("", "end", text=section)
            if isinstance(self.config[section], dict):
                for key, value in self.config[section].items():
                    self.tree.insert(parent, "end", text=key, values=(str(value),))
        
        self.tree.pack(fill="both", expand=True)
        ttk.Button(editor_frame, text="保存配置", command=self.save_config).pack(pady=10)

    # 功能模块实现
    def run_script(self, script_num, args=None):
        """执行指定脚本"""
        cmd = ["python3", SCRIPT_MAP[script_num]]
        if args: cmd.extend(args)
        
        try:
            subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            messagebox.showinfo("执行成功", f"脚本 {script_num} 已启动")
        except Exception as e:
            messagebox.showerror("执行错误", str(e))

    def run_update(self):
        self.run_script(1)

    def open_poc_generator(self):
        """POC生成器弹窗"""
        window = tk.Toplevel(self.master)
        window.title("AI-POC生成器")
        
        ttk.Label(window, text="漏洞文档URL:").grid(row=0, column=0, padx=5, pady=5)
        url_entry = ttk.Entry(window, width=40)
        url_entry.insert(0, self.config["api_settings"]["vuln_article_url"])
        url_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(window, text="生成", 
                  command=lambda: self.run_script(2, ["-u", url_entry.get()])).grid(row=1, columnspan=2)

    def open_scanner(self):
        """扫描目标输入"""
        window = tk.Toplevel(self.master)
        window.title("目标扫描设置")
        
        # 目标输入模式选择
        mode = tk.IntVar(value=1)
        ttk.Radiobutton(window, text="文件输入", variable=mode, value=1).grid(row=0, column=0)
        ttk.Radiobutton(window, text="直接输入", variable=mode, value=2).grid(row=0, column=1)
        
        # 文件选择组件
        file_entry = ttk.Entry(window, width=35)
        ttk.Button(window, text="浏览...", 
                  command=lambda: file_entry.insert(0, filedialog.askopenfilename())).grid(row=1, column=1)
        
        # 直接输入组件
        direct_entry = ttk.Entry(window, width=35)
        
        # 动态切换布局
        def switch_mode():
            file_entry.grid_remove() if mode.get() == 2 else file_entry.grid(row=1, column=0)
            direct_entry.grid_remove() if mode.get() == 1 else direct_entry.grid(row=2, column=0)
        
        ttk.Button(window, text="开始扫描",
                  command=lambda: self.start_scan(mode.get(), file_entry.get(), direct_entry.get())).grid(row=3, columnspan=2)
        mode.trace("w", lambda *_: switch_mode())

    def start_scan(self, mode, file_path, targets):
        """启动扫描逻辑"""
        if mode == 1 and not Path(file_path).exists():
            messagebox.showerror("错误", "目标文件不存在")
            return
        args = ["-t", file_path] if mode == 1 else ["-d", targets]
        self.run_script(3, args)

    def show_config_editor(self):
        self.config_window.deiconify()

    def save_config(self):
        """保存配置到文件"""
        new_config = {}
        for section in self.tree.get_children():
            section_name = self.tree.item(section)["text"]
            new_config[section_name] = {}
            for item in self.tree.get_children(section):
                key = self.tree.item(item)["text"]
                value = self.tree.item(item)["values"][0]
                new_config[section_name][key] = self.parse_value(value)
        
        with open(CONFIG_PATH, "w") as f:
            json.dump(new_config, f, indent=4)
        messagebox.showinfo("成功", "配置已保存")

    # 辅助方法
    def load_config(self):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    
    def parse_value(self, value):
        """类型自动转换"""
        try: return json.loads(value)
        except: return value

    def run_download(self):
        """执行POC库下载脚本"""
        try:
            # 调用第四个脚本（需确保4-Download_POCs.py存在）
            subprocess.Popen(["python3", "4-Download_POCs.py"], 
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
            messagebox.showinfo("执行成功", "POC库下载任务已启动")
        except Exception as e:
            messagebox.showerror("错误", f"启动失败：{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("300x400")
    app = NucleiGUI(root)
    root.mainloop()