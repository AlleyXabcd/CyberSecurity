import socket
import struct
import threading
import os
import json
import time

class NetworkManager:
    """
    网络通信管理器，处理消息和文件的发送和接收
    """
    # 消息类型定义
    MSG_TYPE_DH_PUBLIC_KEY = 1  # Diffie-Hellman公钥交换
    MSG_TYPE_TEXT = 2           # 文本消息
    MSG_TYPE_FILE = 3           # 文件传输
    MSG_TYPE_FILE_REQUEST = 4   # 请求发送文件
    
    def __init__(self, is_server=False, host='127.0.0.1', port=9999):
        """
        初始化网络管理器
        :param is_server: 是否为服务器端
        :param host: 主机地址
        :param port: 端口号
        """
        self.is_server = is_server
        self.host = host
        self.port = port
        self.socket = None
        self.connection = None
        self.connected = False
        self.connection_callback = None
        self.message_callback = None
        self.dh_key_callback = None
        self.file_callback = None
        self.file_request_callback = None
        
    def start(self):
        """
        启动网络服务
        :return: 成功返回True，失败返回False
        """
        try:
            if self.is_server:
                # 作为服务器启动
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.socket.bind((self.host, self.port))
                self.socket.listen(1)
                
                # 在新线程中等待连接
                threading.Thread(target=self._wait_for_connection, daemon=True).start()
                return True
            else:
                # 作为客户端连接服务器
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                self.connection = self.socket
                self.connected = True
                
                # 在新线程中接收消息
                threading.Thread(target=self._receive_messages, daemon=True).start()
                
                # 触发连接回调
                if self.connection_callback:
                    self.connection_callback(True)
                return True
        except Exception as e:
            print(f"网络启动错误: {e}")
            if self.connection_callback:
                self.connection_callback(False)
            return False
    
    def _wait_for_connection(self):
        """
        等待客户端连接（仅服务器端使用）
        """
        try:
            print("等待客户端连接...")
            self.connection, client_address = self.socket.accept()
            self.connected = True
            print(f"客户端 {client_address} 已连接")
            
            # 触发连接回调
            if self.connection_callback:
                self.connection_callback(True)
            
            # 开始接收消息
            self._receive_messages()
        except Exception as e:
            print(f"等待连接时出错: {e}")
            if self.connection_callback:
                self.connection_callback(False)
    
    def _receive_messages(self):
        """
        接收消息的循环
        """
        try:
            while self.connected:
                # 读取消息头部 (消息类型和消息长度)
                header = self.connection.recv(8)
                if not header or len(header) != 8:
                    raise Exception("连接已关闭")
                
                msg_type, msg_len = struct.unpack("!II", header)
                
                # 读取消息内容
                data = b""
                remaining = msg_len
                while remaining > 0:
                    chunk = self.connection.recv(min(4096, remaining))
                    if not chunk:
                        raise Exception("连接已关闭")
                    data += chunk
                    remaining -= len(chunk)
                
                # 根据消息类型处理不同的消息
                self._handle_message(msg_type, data)
                
        except Exception as e:
            print(f"接收消息时出错: {e}")
            self.connected = False
            if self.connection_callback:
                self.connection_callback(False)
    
    def _handle_message(self, msg_type, data):
        """
        处理接收到的消息
        :param msg_type: 消息类型
        :param data: 消息数据
        """
        try:
            if msg_type == self.MSG_TYPE_DH_PUBLIC_KEY:
                # Diffie-Hellman公钥
                public_key = int(data.decode('utf-8'))
                if self.dh_key_callback:
                    self.dh_key_callback(public_key)
                    
            elif msg_type == self.MSG_TYPE_TEXT:
                # 加密的文本消息
                if self.message_callback:
                    self.message_callback(data)
                    
            elif msg_type == self.MSG_TYPE_FILE:
                # 加密的文件数据
                file_info_size = struct.unpack("!I", data[:4])[0]
                file_info_json = data[4:4+file_info_size].decode('utf-8')
                file_info = json.loads(file_info_json)
                file_data = data[4+file_info_size:]
                
                if self.file_callback:
                    self.file_callback(file_info, file_data)
                    
            elif msg_type == self.MSG_TYPE_FILE_REQUEST:
                # 文件传输请求
                file_info = json.loads(data.decode('utf-8'))
                if self.file_request_callback:
                    self.file_request_callback(file_info)
                    
        except Exception as e:
            print(f"处理消息时出错: {e}")
    
    def send_dh_public_key(self, public_key):
        """
        发送Diffie-Hellman公钥
        :param public_key: 公钥
        :return: 是否发送成功
        """
        # 将公钥转换为字符串
        data = str(public_key).encode('utf-8')
        return self._send_message(self.MSG_TYPE_DH_PUBLIC_KEY, data)
    
    def send_encrypted_message(self, encrypted_data):
        """
        发送加密的消息
        :param encrypted_data: 已加密的数据
        :return: 是否发送成功
        """
        return self._send_message(self.MSG_TYPE_TEXT, encrypted_data)
    
    def send_encrypted_file(self, file_path, encrypted_data):
        """
        发送加密的文件
        :param file_path: 文件路径
        :param encrypted_data: 已加密的文件数据
        :return: 是否发送成功
        """
        file_name = os.path.basename(file_path)
        file_info = {
            'name': file_name,
            'size': len(encrypted_data),
            'timestamp': time.time()
        }
        file_info_json = json.dumps(file_info).encode('utf-8')
        file_info_size = len(file_info_json)
        
        # 组合文件信息和文件数据
        # 格式: [文件信息长度(4字节)][文件信息JSON][加密的文件数据]
        payload = struct.pack("!I", file_info_size) + file_info_json + encrypted_data
        
        return self._send_message(self.MSG_TYPE_FILE, payload)
    
    def send_file_request(self, file_path):
        """
        发送文件传输请求
        :param file_path: 要传输的文件路径
        :return: 是否发送成功
        """
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        file_info = {
            'name': file_name,
            'size': file_size,
            'path': file_path,
            'timestamp': time.time()
        }
        
        data = json.dumps(file_info).encode('utf-8')
        return self._send_message(self.MSG_TYPE_FILE_REQUEST, data)
    
    def _send_message(self, msg_type, data):
        """
        发送消息
        :param msg_type: 消息类型
        :param data: 消息数据
        :return: 是否发送成功
        """
        if not self.connected or not self.connection:
            return False
        
        try:
            # 准备消息头部 (消息类型和消息长度)
            header = struct.pack("!II", msg_type, len(data))
            
            # 发送头部和数据
            self.connection.sendall(header + data)
            return True
        except Exception as e:
            print(f"发送消息时出错: {e}")
            self.connected = False
            if self.connection_callback:
                self.connection_callback(False)
            return False
    
    def set_connection_callback(self, callback):
        """
        设置连接状态回调
        :param callback: 回调函数(connected) -> None
        """
        self.connection_callback = callback
    
    def set_message_callback(self, callback):
        """
        设置消息接收回调
        :param callback: 回调函数(encrypted_data) -> None
        """
        self.message_callback = callback
    
    def set_dh_key_callback(self, callback):
        """
        设置Diffie-Hellman公钥接收回调
        :param callback: 回调函数(public_key) -> None
        """
        self.dh_key_callback = callback
    
    def set_file_callback(self, callback):
        """
        设置文件接收回调
        :param callback: 回调函数(file_info, encrypted_data) -> None
        """
        self.file_callback = callback
    
    def set_file_request_callback(self, callback):
        """
        设置文件请求回调
        :param callback: 回调函数(file_info) -> None
        """
        self.file_request_callback = callback
    
    def close(self):
        """
        关闭连接
        """
        self.connected = False
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
            self.connection = None
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None 