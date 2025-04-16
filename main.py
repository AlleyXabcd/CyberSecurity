import os
import sys
import time
import threading
import tkinter as tk
from tkinter import messagebox

# 添加当前目录到模块搜索路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.main_window import MainWindow
from crypto.diffie_hellman import DiffieHellman
from crypto.des import DESCipher
from network.communication import NetworkManager

class Application:
    """
    应用程序主类，连接UI、加密和网络组件
    """
    def __init__(self):
        """
        初始化应用程序
        """
        # 创建UI窗口
        self.window = MainWindow()
        
        # 设置回调函数
        self.window.on_send_message = self.send_message
        self.window.on_send_file = self.send_file
        self.window.on_connect = self.connect_to_server
        self.window.on_start_server = self.start_server
        self.window.on_disconnect = self.disconnect
        self.window.on_clear_process_log = self.clear_process_log
        
        # 初始化网络、加密组件
        self.network = None
        self.dh = None
        self.des = None
        
        # 加密统计
        self.encryption_times = []
        self.decryption_times = []
        
        # 对方的公钥
        self.other_public_key = None
        
        # 标记是否已完成密钥交换
        self.key_exchange_completed = False
    
    def run(self):
        """
        运行应用程序
        """
        self.window.show()
    
    def clear_process_log(self):
        """
        清空加密解密过程日志
        """
        pass  # 只需清空UI中的日志，无需其他操作
    
    def _des_process_callback(self, step_name, step_info=""):
        """
        DES加密/解密过程回调函数
        :param step_name: 步骤名称
        :param step_info: 步骤信息
        """
        # 判断是加密还是解密过程
        is_encryption = True
        if "解密" in step_name or "移除填充" in step_name:
            is_encryption = False
            
        # 添加到UI日志
        self.window.add_process_log(step_name, step_info, is_encryption)
    
    def start_server(self, host, port):
        """
        启动服务器
        :param host: 主机地址
        :param port: 端口号
        """
        try:
            # 创建网络管理器(服务器模式)
            self.network = NetworkManager(is_server=True, host=host, port=port)
            
            # 设置回调函数
            self._setup_network_callbacks()
            
            # 启动网络服务
            if self.network.start():
                self.window.status_label.config(text="等待客户端连接...")
                
                # 初始化Diffie-Hellman
                self.dh = DiffieHellman()
                
                # 更新UI状态
                self.window.set_encryption_status("等待密钥交换...")
            else:
                self.window.connect_button.config(state=tk.NORMAL)
                self.window.show_error("错误", "无法启动服务器")
        except Exception as e:
            self.window.connect_button.config(state=tk.NORMAL)
            self.window.show_error("错误", f"启动服务器时出错: {str(e)}")
    
    def connect_to_server(self, host, port):
        """
        连接到服务器
        :param host: 服务器地址
        :param port: 服务器端口
        """
        try:
            # 创建网络管理器(客户端模式)
            self.network = NetworkManager(is_server=False, host=host, port=port)
            
            # 设置回调函数
            self._setup_network_callbacks()
            
            # 启动网络服务
            if self.network.start():
                # 初始化Diffie-Hellman
                self.dh = DiffieHellman()
                
                # 发送公钥
                self.network.send_dh_public_key(self.dh.get_public_key())
                
                # 更新UI状态
                self.window.set_encryption_status("正在进行密钥交换...")
            else:
                self.window.connect_button.config(state=tk.NORMAL)
                self.window.show_error("错误", "无法连接到服务器")
        except Exception as e:
            self.window.connect_button.config(state=tk.NORMAL)
            self.window.show_error("错误", f"连接服务器时出错: {str(e)}")
    
    def _setup_network_callbacks(self):
        """
        设置网络回调函数
        """
        # 连接状态回调
        self.network.set_connection_callback(self._on_connection_status_changed)
        
        # Diffie-Hellman公钥回调
        self.network.set_dh_key_callback(self._on_dh_key_received)
        
        # 消息接收回调
        self.network.set_message_callback(self._on_encrypted_message_received)
        
        # 文件接收回调
        self.network.set_file_callback(self._on_encrypted_file_received)
        
        # 文件请求回调
        self.network.set_file_request_callback(self._on_file_request_received)
    
    def _on_connection_status_changed(self, connected):
        """
        连接状态变化回调
        :param connected: 是否已连接
        """
        self.window.set_connected(connected)
        
        if not connected:
            # 重置加密状态
            self.des = None
            self.dh = None
            self.other_public_key = None
            self.key_exchange_completed = False
            
            # 更新UI
            self.window.set_key_exchange_status(False)
            self.window.set_encryption_status("")
    
    def _on_dh_key_received(self, public_key):
        """
        接收到Diffie-Hellman公钥
        :param public_key: 对方的公钥
        """
        self.other_public_key = public_key
        
        # 如果是服务器端，收到公钥后发送自己的公钥
        if self.network.is_server:
            self.network.send_dh_public_key(self.dh.get_public_key())
        
        # 生成共享密钥
        shared_secret = self.dh.generate_shared_secret(public_key)
        
        # 添加到加密过程日志
        self.window.add_process_log("Diffie-Hellman密钥交换", 
                                   f"生成共享密钥: {shared_secret[:8].hex()}...", 
                                   True)
        
        # 创建DES加密器
        self.des = DESCipher(shared_secret)
        
        # 设置加密解密过程回调
        self.des.set_process_callback(self._des_process_callback)
        
        # 标记密钥交换完成
        self.key_exchange_completed = True
        
        # 更新UI
        self.window.set_key_exchange_status(True)
        self.window.set_encryption_status("密钥交换完成")
    
    def _on_encrypted_message_received(self, encrypted_data):
        """
        接收到加密消息
        :param encrypted_data: 加密的消息数据
        """
        if not self.key_exchange_completed or not self.des:
            self.window.show_error("错误", "收到消息，但密钥交换尚未完成")
            return
        
        try:
            # 记录接收信息
            self.window.add_process_log("接收加密消息", f"长度: {len(encrypted_data)}字节", False)
            
            # 解密消息
            decrypted_data, decryption_time = self.des.decrypt(encrypted_data)
            
            if decrypted_data is None:
                self.window.show_error("错误", "消息解密失败")
                return
            
            # 解码消息
            message = decrypted_data.decode('utf-8')
            
            # 添加到消息记录
            self.window.add_message(message, is_sent=False)
            
            # 记录解密时间
            self.decryption_times.append((len(encrypted_data), decryption_time))
            self._update_decryption_rate()
            
        except Exception as e:
            self.window.show_error("错误", f"处理接收到的消息时出错: {str(e)}")
    
    def _on_encrypted_file_received(self, file_info, encrypted_data):
        """
        接收到加密文件
        :param file_info: 文件信息
        :param encrypted_data: 加密的文件数据
        """
        if not self.key_exchange_completed or not self.des:
            self.window.show_error("错误", "收到文件，但密钥交换尚未完成")
            return
        
        try:
            # 记录接收信息
            self.window.add_process_log(
                "接收加密文件", 
                f"文件: {file_info['name']}, 加密长度: {len(encrypted_data)}字节", 
                False
            )
            
            # 解密文件数据
            decrypted_data, decryption_time = self.des.decrypt(encrypted_data)
            
            if decrypted_data is None:
                self.window.show_error("错误", "文件解密失败")
                return
            
            # 创建接收文件目录
            received_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "received")
            os.makedirs(received_dir, exist_ok=True)
            
            # 保存文件
            file_name = file_info['name']
            file_path = os.path.join(received_dir, file_name)
            
            # 如果文件已存在，添加时间戳
            if os.path.exists(file_path):
                name, ext = os.path.splitext(file_name)
                timestamp = int(time.time())
                file_name = f"{name}_{timestamp}{ext}"
                file_path = os.path.join(received_dir, file_name)
            
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
            
            # 更新UI
            self.window.add_file_transfer(file_name, len(decrypted_data), is_sent=False)
            self.window.show_info("文件接收", f"文件 {file_name} 已保存到 {file_path}")
            
            # 记录解密时间
            self.decryption_times.append((len(encrypted_data), decryption_time))
            self._update_decryption_rate()
            
        except Exception as e:
            self.window.show_error("错误", f"处理接收到的文件时出错: {str(e)}")
    
    def _on_file_request_received(self, file_info):
        """
        接收到文件请求
        :param file_info: 文件信息
        """
        # 未实现，可用于文件请求确认功能
        pass
    
    def send_message(self, message):
        """
        发送消息
        :param message: 消息内容
        """
        if not self.network or not self.network.connected:
            self.window.show_error("错误", "未连接到网络")
            return
        
        if not self.key_exchange_completed or not self.des:
            self.window.show_error("错误", "密钥交换尚未完成，无法发送加密消息")
            return
        
        try:
            # 添加到加密过程日志
            self.window.add_process_log("准备发送消息", f"内容长度: {len(message)}字符", True)
            
            # 编码消息
            message_bytes = message.encode('utf-8')
            
            # 加密消息
            encrypted_data, encryption_time = self.des.encrypt(message_bytes)
            
            # 发送加密消息
            if self.network.send_encrypted_message(encrypted_data):
                # 更新UI
                self.window.add_message(message, is_sent=True)
                
                # 记录加密时间
                self.encryption_times.append((len(message_bytes), encryption_time))
                self._update_encryption_rate()
                
                # 记录发送信息
                self.window.add_process_log(
                    "消息发送完成", 
                    f"原始长度: {len(message_bytes)}字节, 加密长度: {len(encrypted_data)}字节", 
                    True
                )
            else:
                self.window.show_error("错误", "发送消息失败")
                
        except Exception as e:
            self.window.show_error("错误", f"发送消息时出错: {str(e)}")
    
    def send_file(self, file_path):
        """
        发送文件
        :param file_path: 文件路径
        """
        if not self.network or not self.network.connected:
            self.window.show_error("错误", "未连接到网络")
            return
        
        if not self.key_exchange_completed or not self.des:
            self.window.show_error("错误", "密钥交换尚未完成，无法发送加密文件")
            return
        
        try:
            # 获取文件大小和名称
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # 添加到加密过程日志
            self.window.add_process_log(
                "准备发送文件", 
                f"文件: {file_name}, 大小: {file_size}字节", 
                True
            )
            
            # 读取文件
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # 加密文件
            encrypted_data, encryption_time = self.des.encrypt(file_data)
            
            # 发送加密文件
            if self.network.send_encrypted_file(file_path, encrypted_data):
                # 更新UI
                self.window.add_file_transfer(file_name, len(file_data), is_sent=True)
                
                # 记录加密时间
                self.encryption_times.append((len(file_data), encryption_time))
                self._update_encryption_rate()
                
                # 记录发送信息
                self.window.add_process_log(
                    "文件发送完成", 
                    f"原始大小: {len(file_data)}字节, 加密大小: {len(encrypted_data)}字节", 
                    True
                )
            else:
                self.window.show_error("错误", "发送文件失败")
                
        except Exception as e:
            self.window.show_error("错误", f"发送文件时出错: {str(e)}")
    
    def _update_encryption_rate(self):
        """
        更新加密速率统计
        """
        if not self.encryption_times:
            return
        
        # 计算平均加密速率 (字节/秒)
        total_bytes = sum(size for size, _ in self.encryption_times)
        total_time = sum(time for _, time in self.encryption_times)
        
        if total_time > 0:
            avg_rate = total_bytes / total_time
            self.window.update_encryption_rate(avg_rate)
    
    def _update_decryption_rate(self):
        """
        更新解密速率统计
        """
        if not self.decryption_times:
            return
        
        # 计算平均解密速率 (字节/秒)
        total_bytes = sum(size for size, _ in self.decryption_times)
        total_time = sum(time for _, time in self.decryption_times)
        
        if total_time > 0:
            avg_rate = total_bytes / total_time
            self.window.update_decryption_rate(avg_rate)
    
    def disconnect(self):
        """
        断开连接
        """
        if self.network:
            self.network.close()
            self.network = None
        
        # 重置加密组件
        self.des = None
        self.dh = None
        self.other_public_key = None
        self.key_exchange_completed = False
        
        # 更新UI
        self.window.set_connected(False)
        self.window.set_key_exchange_status(False)
        self.window.set_encryption_status("")


if __name__ == "__main__":
    app = Application()
    app.run()