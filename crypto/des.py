from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import time
import os

class DESCipher:
    def __init__(self, key):
        """
        初始化DES加密器，使用CBC模式
        :param key: 8字节密钥
        """
        self.key = key
        self.block_size = 8  # DES块大小为8字节

    def encrypt(self, data):
        """
        加密数据，使用CBC模式
        :param data: 需要加密的数据(bytes)
        :return: (iv + 加密后的数据, 加密时间)
        """
        # 生成随机IV
        iv = os.urandom(8)
        
        # 创建加密器
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        
        # 记录开始时间
        start_time = time.time()
        
        # 对数据进行填充然后加密
        padded_data = pad(data, self.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # 计算加密时间
        encryption_time = time.time() - start_time
        
        # 返回IV + 加密数据以及加密时间
        return iv + encrypted_data, encryption_time

    def decrypt(self, data):
        """
        解密数据，使用CBC模式
        :param data: 加密后的数据，包含IV(前8字节)
        :return: (解密后的数据, 解密时间)
        """
        # 提取IV和加密数据
        iv = data[:8]
        encrypted_data = data[8:]
        
        # 创建解密器
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        
        # 记录开始时间
        start_time = time.time()
        
        # 解密数据并去除填充
        decrypted_data = cipher.decrypt(encrypted_data)
        try:
            unpadded_data = unpad(decrypted_data, self.block_size)
        except ValueError:
            # 如果解密过程出错，返回None
            unpadded_data = None
        
        # 计算解密时间
        decryption_time = time.time() - start_time
        
        return unpadded_data, decryption_time
    
    @staticmethod
    def calculate_encryption_efficiency(original_size, encrypted_size, encryption_time):
        """
        计算加密效率
        :param original_size: 原始数据大小(字节)
        :param encrypted_size: 加密后数据大小(字节)
        :param encryption_time: 加密时间(秒)
        :return: 加密效率(字节/秒)
        """
        return original_size / encryption_time if encryption_time > 0 else 0 