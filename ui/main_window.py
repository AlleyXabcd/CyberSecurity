import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, Toplevel
import os
import threading
import time
from datetime import datetime

class MainWindow:
    """
    主窗口界面
    """
    def __init__(self, title="DES加密通信系统"):
        """
        初始化主窗口
        :param title: 窗口标题
        """
        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry("1000x800")
        self.root.minsize(800, 500)
        
        # 回调函数
        self.on_send_message = None
        self.on_send_file = None
        self.on_connect = None
        self.on_start_server = None
        self.on_disconnect = None
        
        # 创建UI组件
        self._create_ui()
        
        # 设置主题样式
        self._set_style()
    
    def _set_style(self):
        """
        设置UI主题样式
        """
        style = ttk.Style()
        
        # 尝试使用主题
        try:
            style.theme_use('clam')
        except:
            pass
        
        # 按钮样式
        style.configure('Primary.TButton', 
                        background='#4a86e8', 
                        foreground='white',
                        padding=5)
        
        # 标签样式
        style.configure('Header.TLabel',
                        font=('Arial', 14, 'bold'))
        
        style.configure('Status.TLabel',
                        font=('Arial', 10),
                        padding=5)
        
        # 加密过程显示样式
        style.configure('Crypto.TLabel',
                        font=('Courier New', 10),
                        padding=3)
    
    def _create_ui(self):
        """
        创建UI组件
        """
        # 创建主布局为左右两个面板
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 左侧面板 (消息和状态)
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=3)
        
        # 右侧面板 (网络连接和文件传输)
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=1)
        
        # 左侧上方：消息显示区域
        messages_label = ttk.Label(left_frame, text="消息记录", style='Header.TLabel')
        messages_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.messages_text = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD, height=15)
        self.messages_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.messages_text.config(state=tk.DISABLED)
        
        # 初始化消息文本区域的标签样式
        self._setup_message_tags()
        
        # 左侧中间：加密过程显示
        crypto_label_frame = ttk.Frame(left_frame)
        crypto_label_frame.pack(fill=tk.X, pady=(0, 5))
        
        crypto_label = ttk.Label(crypto_label_frame, text="DES加密/解密过程", style='Header.TLabel')
        crypto_label.pack(side=tk.LEFT)
        
        # 添加详情按钮
        self.details_button = ttk.Button(crypto_label_frame, text="查看详情", 
                                       command=self._show_crypto_details)
        self.details_button.pack(side=tk.RIGHT)
        
        crypto_frame = ttk.LabelFrame(left_frame, text="加密/解密信息")
        crypto_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 原文显示
        plaintext_frame = ttk.Frame(crypto_frame)
        plaintext_frame.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(plaintext_frame, text="原文:", width=10).pack(side=tk.LEFT)
        self.plaintext_display = ttk.Label(plaintext_frame, text="", style='Crypto.TLabel')
        self.plaintext_display.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 密钥显示
        key_frame = ttk.Frame(crypto_frame)
        key_frame.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(key_frame, text="密钥:", width=10).pack(side=tk.LEFT)
        self.key_display = ttk.Label(key_frame, text="", style='Crypto.TLabel')
        self.key_display.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 密文显示
        ciphertext_frame = ttk.Frame(crypto_frame)
        ciphertext_frame.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(ciphertext_frame, text="密文:", width=10).pack(side=tk.LEFT)
        self.ciphertext_display = ttk.Label(ciphertext_frame, text="", style='Crypto.TLabel')
        self.ciphertext_display.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 初始化加密数据存储
        self._current_crypto_data = {
            'plaintext': b'',
            'key': b'',
            'ciphertext': b'',
            'is_encrypting': True
        }
        
        # 左侧下方：消息输入和发送
        input_frame = ttk.Frame(left_frame)
        input_frame.pack(fill=tk.BOTH, pady=(0, 5))
        
        self.message_input = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=5)
        self.message_input.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        
        buttons_frame = ttk.Frame(input_frame)
        buttons_frame.pack(side=tk.RIGHT, padx=(5, 0), fill=tk.Y)
        
        self.send_button = ttk.Button(buttons_frame, text="发送", style='Primary.TButton',
                                     command=self._on_send_button_click)
        self.send_button.pack(fill=tk.X, pady=(0, 5))
        
        self.send_file_button = ttk.Button(buttons_frame, text="发送文件", 
                                         command=self._on_send_file_button_click)
        self.send_file_button.pack(fill=tk.X)
        
        # 左侧底部：状态信息
        status_frame = ttk.Frame(left_frame)
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.status_label = ttk.Label(status_frame, text="未连接", style='Status.TLabel')
        self.status_label.pack(side=tk.LEFT)
        
        self.encryption_status = ttk.Label(status_frame, text="", style='Status.TLabel')
        self.encryption_status.pack(side=tk.RIGHT)
        
        # 右侧上方：连接设置
        connection_label = ttk.Label(right_frame, text="连接设置", style='Header.TLabel')
        connection_label.pack(anchor=tk.W, pady=(0, 5))
        
        connection_frame = ttk.LabelFrame(right_frame, text="网络配置")
        connection_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 角色选择
        role_frame = ttk.Frame(connection_frame)
        role_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(role_frame, text="角色:").pack(side=tk.LEFT)
        
        self.role_var = tk.StringVar(value="client")
        ttk.Radiobutton(role_frame, text="Alice (客户端)", variable=self.role_var, 
                      value="client").pack(side=tk.LEFT, padx=(5, 10))
        ttk.Radiobutton(role_frame, text="Bob (服务器)", variable=self.role_var, 
                      value="server").pack(side=tk.LEFT)
        
        # 地址和端口
        host_frame = ttk.Frame(connection_frame)
        host_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(host_frame, text="地址:").pack(side=tk.LEFT)
        self.host_entry = ttk.Entry(host_frame)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(side=tk.LEFT, padx=(5, 10), fill=tk.X, expand=True)
        
        ttk.Label(host_frame, text="端口:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(host_frame, width=6)
        self.port_entry.insert(0, "9999")
        self.port_entry.pack(side=tk.LEFT, padx=(5, 0))
        
        # 连接按钮
        self.connect_button = ttk.Button(connection_frame, text="连接", 
                                       style='Primary.TButton',
                                       command=self._on_connect_button_click)
        self.connect_button.pack(fill=tk.X, padx=5, pady=5)
        
        # 右侧中间：加密信息
        encryption_label = ttk.Label(right_frame, text="加密信息", style='Header.TLabel')
        encryption_label.pack(anchor=tk.W, pady=(10, 5))
        
        encryption_frame = ttk.LabelFrame(right_frame, text="DES + Diffie-Hellman")
        encryption_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 加密统计信息
        self.encryption_info = ttk.Treeview(encryption_frame, columns=("value",), 
                                         show="tree", height=6)
        self.encryption_info.pack(fill=tk.X, padx=5, pady=5)
        
        self.encryption_info.column("#0", width=150)
        self.encryption_info.column("value", width=100)
        
        # 添加初始统计项
        self.encryption_info.insert("", tk.END, text="密钥交换状态", values=["未完成"], iid="key_exchange")
        self.encryption_info.insert("", tk.END, text="发送消息数量", values=["0"], iid="sent_msgs")
        self.encryption_info.insert("", tk.END, text="接收消息数量", values=["0"], iid="recv_msgs")
        self.encryption_info.insert("", tk.END, text="发送文件数量", values=["0"], iid="sent_files")
        self.encryption_info.insert("", tk.END, text="接收文件数量", values=["0"], iid="recv_files")
        self.encryption_info.insert("", tk.END, text="平均加密效率", values=["0 B/s"], iid="encryption_rate")
        self.encryption_info.insert("", tk.END, text="平均解密效率", values=["0 B/s"], iid="decryption_rate")
        
        # 右侧底部：文件传输
        files_label = ttk.Label(right_frame, text="文件传输", style='Header.TLabel')
        files_label.pack(anchor=tk.W, pady=(10, 5))
        
        files_frame = ttk.LabelFrame(right_frame, text="传输记录")
        files_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.files_tree = ttk.Treeview(files_frame, 
                                     columns=("direction", "size", "time"),
                                     show="headings")
        self.files_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.files_tree.heading("direction", text="方向")
        self.files_tree.heading("size", text="大小")
        self.files_tree.heading("time", text="时间")
        
        self.files_tree.column("direction", width=60)
        self.files_tree.column("size", width=60)
        self.files_tree.column("time", width=120)
        
        # 初始化UI状态
        self._update_ui_state(connected=False)
    
    def _on_send_button_click(self):
        """
        发送按钮点击处理
        """
        message = self.message_input.get("1.0", tk.END).strip()
        if not message:
            return
        
        if self.on_send_message:
            self.on_send_message(message)
            
        # 清空输入框
        self.message_input.delete("1.0", tk.END)
    
    def _on_send_file_button_click(self):
        """
        发送文件按钮点击处理
        """
        file_path = filedialog.askopenfilename(title="选择要发送的文件")
        if not file_path:
            return
        
        if self.on_send_file:
            self.on_send_file(file_path)
    
    def _on_connect_button_click(self):
        """
        连接按钮点击处理
        """
        if not self.is_connected():
            try:
                host = self.host_entry.get().strip()
                port = int(self.port_entry.get().strip())
                is_server = self.role_var.get() == "server"
                
                if self.on_connect and is_server:
                    self.connect_button.config(state=tk.DISABLED)
                    self.status_label.config(text="正在启动服务器...")
                    self.on_start_server(host, port)
                elif self.on_connect:
                    self.connect_button.config(state=tk.DISABLED)
                    self.status_label.config(text="正在连接...")
                    self.on_connect(host, port)
                
            except ValueError:
                messagebox.showerror("错误", "端口必须是数字")
        else:
            if self.on_disconnect:
                self.on_disconnect()
    
    def _update_ui_state(self, connected):
        """
        更新UI状态
        :param connected: 是否已连接
        """
        if connected:
            self.send_button.config(state=tk.NORMAL)
            self.send_file_button.config(state=tk.NORMAL)
            self.connect_button.config(text="断开", state=tk.NORMAL)
            
            # 禁用连接设置
            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            
            # 禁用角色选择按钮
            self._update_radiobuttons_state(self.root, tk.DISABLED)
        else:
            self.send_button.config(state=tk.DISABLED)
            self.send_file_button.config(state=tk.DISABLED)
            self.connect_button.config(text="连接", state=tk.NORMAL)
            
            # 启用连接设置
            self.host_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)
            
            # 启用角色选择按钮
            self._update_radiobuttons_state(self.root, tk.NORMAL)
    
    def _update_radiobuttons_state(self, parent, state):
        """
        递归更新所有Radiobutton的状态
        :param parent: 父组件
        :param state: 要设置的状态
        """
        # 检查当前组件的所有子组件
        for child in parent.winfo_children():
            if isinstance(child, ttk.Radiobutton):
                child.config(state=state)
            # 递归检查子组件的子组件
            self._update_radiobuttons_state(child, state)
    
    def show(self):
        """
        显示主窗口
        """
        self.root.mainloop()
    
    def set_connected(self, connected):
        """
        设置连接状态
        :param connected: 是否已连接
        """
        self._update_ui_state(connected)
        self.status_label.config(text="已连接" if connected else "未连接")
    
    def is_connected(self):
        """
        检查是否已连接
        """
        return self.connect_button.cget("text") == "断开"
    
    def add_message(self, message, is_sent=True):
        """
        添加消息到消息记录
        :param message: 消息内容
        :param is_sent: 是否为发送的消息
        """
        self.messages_text.config(state=tk.NORMAL)
        
        # 添加时间戳和发送方向
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # 在新行开始
        if self.messages_text.index('end-1c') != '1.0':
            self.messages_text.insert(tk.END, "\n")
        
        # 添加时间戳
        self.messages_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        
        # 添加发送/接收标签
        if is_sent:
            self.messages_text.insert(tk.END, "发送: ", "sent")
            bubble_tag = "sent_bubble"
            content_tag = "sent_content"
        else:
            self.messages_text.insert(tk.END, "接收: ", "received")
            bubble_tag = "received_bubble"
            content_tag = "received_content"
        
        # 添加消息内容，使用气泡背景
        content_start = self.messages_text.index(tk.END)
        self.messages_text.insert(tk.END, f"{message}", content_tag)
        content_end = self.messages_text.index(tk.END)
        
        # 应用气泡背景
        self.messages_text.tag_add(bubble_tag, content_start, content_end)
        
        # 自动滚动到底部
        self.messages_text.see(tk.END)
        self.messages_text.config(state=tk.DISABLED)
        
        # 更新统计信息
        if is_sent:
            count = int(self.encryption_info.item("sent_msgs", "values")[0]) + 1
            self.encryption_info.item("sent_msgs", values=[str(count)])
        else:
            count = int(self.encryption_info.item("recv_msgs", "values")[0]) + 1
            self.encryption_info.item("recv_msgs", values=[str(count)])
    
    def add_file_transfer(self, filename, size, is_sent=True):
        """
        添加文件传输记录
        :param filename: 文件名
        :param size: 文件大小(字节)
        :param is_sent: 是否为发送的文件
        """
        direction = "发送" if is_sent else "接收"
        
        # 格式化文件大小
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024*1024:
            size_str = f"{size/1024:.1f} KB"
        else:
            size_str = f"{size/1024/1024:.1f} MB"
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self.files_tree.insert("", tk.END, text=filename, 
                              values=(direction, size_str, timestamp))
        
        # 更新统计信息
        if is_sent:
            count = int(self.encryption_info.item("sent_files", "values")[0]) + 1
            self.encryption_info.item("sent_files", values=[str(count)])
        else:
            count = int(self.encryption_info.item("recv_files", "values")[0]) + 1
            self.encryption_info.item("recv_files", values=[str(count)])
    
    def set_key_exchange_status(self, completed):
        """
        设置密钥交换状态
        :param completed: 是否已完成
        """
        status = "已完成" if completed else "未完成"
        self.encryption_info.item("key_exchange", values=[status])
    
    def update_encryption_rate(self, rate):
        """
        更新加密速率
        :param rate: 加密速率(字节/秒)
        """
        # 格式化速率
        if rate < 1024:
            rate_str = f"{rate:.1f} B/s"
        elif rate < 1024*1024:
            rate_str = f"{rate/1024:.1f} KB/s"
        else:
            rate_str = f"{rate/1024/1024:.1f} MB/s"
            
        self.encryption_info.item("encryption_rate", values=[rate_str])
    
    def update_decryption_rate(self, rate):
        """
        更新解密速率
        :param rate: 解密速率(字节/秒)
        """
        # 格式化速率
        if rate < 1024:
            rate_str = f"{rate:.1f} B/s"
        elif rate < 1024*1024:
            rate_str = f"{rate/1024:.1f} KB/s"
        else:
            rate_str = f"{rate/1024/1024:.1f} MB/s"
            
        self.encryption_info.item("decryption_rate", values=[rate_str])
    
    def show_error(self, title, message):
        """
        显示错误消息
        :param title: 标题
        :param message: 消息内容
        """
        messagebox.showerror(title, message)
    
    def show_info(self, title, message):
        """
        显示信息消息
        :param title: 标题
        :param message: 消息内容
        """
        messagebox.showinfo(title, message)
    
    def set_encryption_status(self, status):
        """
        设置加密状态信息
        :param status: 状态信息
        """
        self.encryption_status.config(text=status)
    
    def update_crypto_display(self, plaintext, key, ciphertext, is_encrypting=True):
        """
        更新加密/解密过程显示
        :param plaintext: 原文 (字符串或字节)
        :param key: 密钥 (字符串或字节)
        :param ciphertext: 密文 (字节)
        :param is_encrypting: 是否为加密过程 (True为加密, False为解密)
        """
        # 保存完整的数据用于详情视图
        self._current_crypto_data = {
            'plaintext': plaintext,
            'key': key,
            'ciphertext': ciphertext,
            'is_encrypting': is_encrypting
        }
        
        # 将字节转换为可显示的十六进制
        def to_display_format(data):
            if isinstance(data, bytes):
                # 将字节转换为十六进制
                hex_data = data.hex()
                # 每两个字符添加一个空格，使其更易读
                formatted = ' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
                # 如果太长，截断并添加省略号
                if len(formatted) > 50:
                    return formatted[:47] + "..."
                return formatted
            elif isinstance(data, str):
                # 如果是字符串，显示前25个字符
                if len(data) > 25:
                    return data[:22] + "..."
                return data
            return str(data)
            
        # 更新显示
        operation = "加密" if is_encrypting else "解密"
        
        self.plaintext_display.config(text=to_display_format(plaintext))
        self.key_display.config(text=to_display_format(key))
        self.ciphertext_display.config(text=to_display_format(ciphertext))
        
        # 也可以在消息区域显示加密/解密操作信息
        self.add_system_message(f"执行{operation}操作 - 原文长度: {len(plaintext)} 字节, 密文长度: {len(ciphertext)} 字节")
    
    def add_system_message(self, message):
        """
        添加系统消息到消息显示区域
        :param message: 系统消息内容
        """
        time_str = datetime.now().strftime('%H:%M:%S')
        
        self.messages_text.config(state=tk.NORMAL)
        
        # 在新行开始
        if self.messages_text.index('end-1c') != '1.0':
            self.messages_text.insert(tk.END, "\n")
        
        # 添加系统消息
        self.messages_text.insert(tk.END, f"[{time_str}] 系统: {message}", "system")
        
        self.messages_text.see(tk.END)
        self.messages_text.config(state=tk.DISABLED)
    
    def _setup_message_tags(self):
        """
        设置消息文本区域的标签样式
        """
        # 配置消息文本区域的标签样式
        self.messages_text.tag_configure("sent", 
                                       foreground="#0066cc", 
                                       font=('Arial', 10, 'bold'))
        self.messages_text.tag_configure("sent_content", 
                                       foreground="#000000",
                                       lmargin1=20,
                                       lmargin2=20)
        
        self.messages_text.tag_configure("received", 
                                       foreground="#006633", 
                                       font=('Arial', 10, 'bold'))
        self.messages_text.tag_configure("received_content", 
                                       foreground="#000000",
                                       lmargin1=20,
                                       lmargin2=20)
        
        self.messages_text.tag_configure("system", 
                                       foreground="#666666", 
                                       font=('Arial', 9, 'italic'))
        
        self.messages_text.tag_configure("timestamp", 
                                       foreground="#888888", 
                                       font=('Arial', 8))
        
        # 创建消息气泡背景样式
        self.messages_text.tag_configure("sent_bubble", 
                                      background="#e6f2ff",
                                      borderwidth=1,
                                      relief=tk.SOLID)
        
        self.messages_text.tag_configure("received_bubble", 
                                      background="#e6ffe6",
                                      borderwidth=1,
                                      relief=tk.SOLID)
    
    def _show_crypto_details(self):
        """
        显示加密/解密详情窗口
        """
        if not hasattr(self, '_current_crypto_data'):
            return
            
        # 创建详情窗口
        details_window = Toplevel(self.root)
        details_window.title("加密/解密详情")
        details_window.geometry("800x600")
        details_window.minsize(600, 400)
        
        # 设置窗口为模态
        details_window.grab_set()
        
        # 详情内容
        main_frame = ttk.Frame(details_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 获取当前数据
        data = self._current_crypto_data
        operation = "加密" if data['is_encrypting'] else "解密"
        
        # 标题
        ttk.Label(main_frame, text=f"DES {operation}详情", font=('Arial', 16, 'bold')).pack(pady=(0, 20))
        
        # 创建一个显示器函数
        def create_display_area(parent, label_text, data, is_hex=False):
            frame = ttk.LabelFrame(parent, text=label_text)
            frame.pack(fill=tk.BOTH, expand=True, pady=5)
            
            text_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=6)
            text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # 格式化并显示数据
            display_text = ""
            if is_hex and isinstance(data, bytes):
                # 十六进制显示，每行16字节
                hex_data = data.hex()
                for i in range(0, len(hex_data), 32):
                    if i > 0:
                        display_text += "\n"
                    chunk = hex_data[i:i+32]
                    formatted = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
                    display_text += formatted
                    
                # 如果数据很少，不需要换行
                if len(hex_data) <= 32:
                    display_text = ' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
            elif isinstance(data, bytes):
                try:
                    # 尝试解码为文本
                    display_text = data.decode('utf-8')
                except UnicodeDecodeError:
                    # 如果解码失败，显示十六进制
                    hex_data = data.hex()
                    for i in range(0, len(hex_data), 32):
                        if i > 0:
                            display_text += "\n"
                        chunk = hex_data[i:i+32]
                        formatted = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
                        display_text += formatted
            else:
                display_text = str(data)
                
            text_area.insert(tk.END, display_text)
            text_area.config(state=tk.DISABLED)  # 设为只读
        
        # 原文显示区域
        create_display_area(main_frame, "原文", data['plaintext'])
        
        # 密钥显示区域 (十六进制)
        create_display_area(main_frame, "密钥 (十六进制)", data['key'], is_hex=True)
        
        # 密文显示区域 (十六进制)
        create_display_area(main_frame, "密文 (十六进制)", data['ciphertext'], is_hex=True)
        
        # 统计信息
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=10)
        
        plaintext_len = len(data['plaintext'])
        ciphertext_len = len(data['ciphertext'])
        
        ttk.Label(stats_frame, text=f"原文大小: {plaintext_len} 字节").pack(side=tk.LEFT, padx=10)
        ttk.Label(stats_frame, text=f"密文大小: {ciphertext_len} 字节").pack(side=tk.LEFT, padx=10)
        
        if data['is_encrypting']:
            overhead = ((ciphertext_len - plaintext_len) / plaintext_len) * 100 if plaintext_len > 0 else 0
            ttk.Label(stats_frame, text=f"加密开销: {overhead:.2f}%").pack(side=tk.LEFT, padx=10)
        
        # 底部关闭按钮
        ttk.Button(main_frame, text="关闭", command=details_window.destroy).pack(pady=10)