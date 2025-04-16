import time
import os

class DESCipher:
    # 初始置换表 IP
    __IP = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]

    # 逆初始置换表 IP^-1
    __IP_1 = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

    # 扩展置换表 E
    __E = [32, 1, 2, 3, 4, 5,
           4, 5, 6, 7, 8, 9,
           8, 9, 10, 11, 12, 13,
           12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21,
           20, 21, 22, 23, 24, 25,
           24, 25, 26, 27, 28, 29,
           28, 29, 30, 31, 32, 1]

    # 置换函数 P
    __P = [16, 7, 20, 21, 29, 12, 28, 17,
           1, 15, 23, 26, 5, 18, 31, 10,
           2, 8, 24, 14, 32, 27, 3, 9,
           19, 13, 30, 6, 22, 11, 4, 25]

    # S盒
    __S_BOX = [
        # S1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],
        # S2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],
        # S3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],
        # S4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],
        # S5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ],
        # S6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ],
        # S7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],
        # S8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ]
    ]

    # 置换选择1 PC-1
    __PC_1 = [57, 49, 41, 33, 25, 17, 9,
              1, 58, 50, 42, 34, 26, 18,
              10, 2, 59, 51, 43, 35, 27,
              19, 11, 3, 60, 52, 44, 36,
              63, 55, 47, 39, 31, 23, 15,
              7, 62, 54, 46, 38, 30, 22,
              14, 6, 61, 53, 45, 37, 29,
              21, 13, 5, 28, 20, 12, 4]

    # 置换选择2 PC-2
    __PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
              15, 6, 21, 10, 23, 19, 12, 4,
              26, 8, 16, 7, 27, 20, 13, 2,
              41, 52, 31, 37, 47, 55, 30, 40,
              51, 45, 33, 48, 44, 49, 39, 56,
              34, 53, 46, 42, 50, 36, 29, 32]

    # 左移位数表
    __SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def __init__(self, key):
        """
        初始化DES加密器
        :param key: 8字节密钥
        """
        # 确保密钥长度为8字节
        if isinstance(key, str):
            self.key = key.encode('utf-8')
        else:
            self.key = key
            
        # 如果密钥长度不足8字节，补充到8字节
        if len(self.key) < 8:
            self.key = self.key + b'\x00' * (8 - len(self.key))
        # 如果密钥长度超过8字节，截取前8字节
        elif len(self.key) > 8:
            self.key = self.key[:8]
            
        # 生成16轮子密钥
        self.process_callback = None  # 初始化回调函数
        self.sub_keys = self.__generate_sub_keys()
        self.block_size = 8  # DES块大小为8字节
        
    def set_process_callback(self, callback):
        """
        设置过程回调函数，用于显示加密解密过程
        :param callback: 回调函数，接收(step_name, step_info)参数
        """
        self.process_callback = callback

    def __notify_process(self, step_name, step_info=""):
        """
        通知过程回调函数
        :param step_name: 步骤名称
        :param step_info: 步骤信息
        """
        if self.process_callback:
            self.process_callback(step_name, step_info)

    def __str_to_bit_array(self, text):
        """
        将字符串转换为比特数组
        :param text: 输入字符串
        :return: 比特数组
        """
        result = []
        for char in text:
            bits = bin(char)[2:].zfill(8)
            result.extend([int(bit) for bit in bits])
        return result

    def __bit_array_to_str(self, bit_array):
        """
        将比特数组转换为字符串
        :param bit_array: 比特数组
        :return: 字符串
        """
        result = []
        for i in range(0, len(bit_array), 8):
            byte = bit_array[i:i+8]
            char = int(''.join([str(bit) for bit in byte]), 2)
            result.append(char)
        return bytes(result)

    def __permute(self, block, table):
        """
        根据置换表对数据块进行置换
        :param block: 输入数据块
        :param table: 置换表
        :return: 置换后的数据块
        """
        return [block[i-1] for i in table]

    def __shift_left(self, block, shifts):
        """
        对数据块进行左移
        :param block: 输入数据块
        :param shifts: 左移位数
        :return: 左移后的数据块
        """
        return block[shifts:] + block[:shifts]

    def __xor(self, a, b):
        """
        对两个比特数组进行异或操作
        :param a: 比特数组a
        :param b: 比特数组b
        :return: 异或结果
        """
        return [a[i] ^ b[i] for i in range(len(a))]

    def __generate_sub_keys(self):
        """
        生成16轮子密钥
        :return: 16轮子密钥列表
        """
        # 将密钥转换为比特数组
        key_bits = self.__str_to_bit_array(self.key)
        self.__notify_process("子密钥生成", f"密钥: {self.key.hex()}")
        
        # PC-1置换，将64位密钥变为56位
        key_56 = self.__permute(key_bits, self.__PC_1)
        self.__notify_process("PC-1置换", f"56位密钥: {''.join(str(bit) for bit in key_56[:8])}...")
        
        # 分为左右两部分，各28位
        left, right = key_56[:28], key_56[28:]
        
        # 生成16轮子密钥
        sub_keys = []
        for i in range(16):
            # 根据轮数进行左移
            left = self.__shift_left(left, self.__SHIFT[i])
            right = self.__shift_left(right, self.__SHIFT[i])
            
            # 合并左右两部分
            combined = left + right
            
            # PC-2置换，将56位变为48位
            sub_key = self.__permute(combined, self.__PC_2)
            sub_keys.append(sub_key)
            
            self.__notify_process(f"生成子密钥 #{i+1}", f"移位: {self.__SHIFT[i]}位, 长度: {len(sub_key)}位")
            
        return sub_keys

    def __f_function(self, right, sub_key, round_num=0):
        """
        DES的F函数
        :param right: 输入数据右半部分(32位)
        :param sub_key: 子密钥(48位)
        :param round_num: 当前轮数(用于显示)
        :return: F函数输出(32位)
        """
        # 扩展置换，将32位扩展到48位
        expanded = self.__permute(right, self.__E)
        self.__notify_process(f"第{round_num+1}轮 - 扩展置换", f"32位 -> 48位")
        
        # 与子密钥进行异或
        xored = self.__xor(expanded, sub_key)
        self.__notify_process(f"第{round_num+1}轮 - 密钥异或", f"子密钥长度: {len(sub_key)}位")
        
        # S盒替代，将48位压缩为32位
        sbox_output = []
        for i in range(8):
            # 取6位输入到S盒
            block = xored[i*6:(i+1)*6]
            
            # 计算S盒的行和列
            row = block[0] * 2 + block[5]
            col = block[1] * 8 + block[2] * 4 + block[3] * 2 + block[4]
            
            # 获取S盒输出值(4位)
            val = self.__S_BOX[i][row][col]
            
            # 将输出值转换为比特
            sbox_output.extend([int(bit) for bit in bin(val)[2:].zfill(4)])
            
        self.__notify_process(f"第{round_num+1}轮 - S盒替代", f"48位 -> 32位")
        
        # P置换
        result = self.__permute(sbox_output, self.__P)
        self.__notify_process(f"第{round_num+1}轮 - P置换", f"32位输出")
        
        return result

    def __des_encrypt_block(self, block, decrypt=False):
        """
        DES加密/解密一个块
        :param block: 输入块(8字节)
        :param decrypt: 是否为解密模式
        :return: 加密/解密后的块
        """
        mode = "解密" if decrypt else "加密"
        self.__notify_process(f"开始{mode}块", f"块大小: {len(block)}字节")
        
        # 将块转换为比特数组
        block = self.__str_to_bit_array(block)
        
        # 初始置换
        block = self.__permute(block, self.__IP)
        self.__notify_process("初始置换IP", f"64位数据")
        
        # 分为左右两部分，各32位
        left, right = block[:32], block[32:]
        self.__notify_process("数据分块", f"左: 32位, 右: 32位")
        
        # 16轮Feistel网络
        for i in range(16):
            # 如果是解密，则使用逆序的子密钥
            key_index = 15 - i if decrypt else i
            
            # 保存原始左半部分
            old_left = left
            
            # 左半部分等于原来的右半部分
            left = right
            
            # 右半部分等于原来的左半部分与F函数输出的异或
            right = self.__xor(old_left, self.__f_function(right, self.sub_keys[key_index], i))
            
            self.__notify_process(f"第{i+1}轮Feistel完成", f"使用子密钥 #{key_index+1}")
        
        # 合并左右两部分(交换左右位置)
        result = right + left
        self.__notify_process("合并左右数据", f"交换左右位置")
        
        # 逆初始置换
        result = self.__permute(result, self.__IP_1)
        self.__notify_process("逆初始置换IP^-1", f"64位数据")
        
        # 将比特数组转换为字节
        output = self.__bit_array_to_str(result)
        self.__notify_process(f"完成{mode}块", f"输出: {len(output)}字节")
        
        return output

    def __pad(self, data):
        """
        使用PKCS#5填充方式，确保数据长度是块大小的倍数
        :param data: 输入数据
        :return: 填充后的数据
        """
        pad_len = self.block_size - (len(data) % self.block_size)
        padding = bytes([pad_len]) * pad_len
        padded = data + padding
        self.__notify_process("PKCS#5填充", f"原始长度: {len(data)}字节, 填充后: {len(padded)}字节, 填充字节: {pad_len}")
        return padded

    def __unpad(self, data):
        """
        移除PKCS#5填充
        :param data: 填充后的数据
        :return: 原始数据
        """
        pad_len = data[-1]
        if pad_len > self.block_size or pad_len == 0:
            self.__notify_process("移除填充失败", f"无效的填充长度: {pad_len}")
            return None  # 无效填充
        for i in range(1, pad_len + 1):
            if data[-i] != pad_len:
                self.__notify_process("移除填充失败", f"填充内容不一致")
                return None  # 无效填充
                
        unpadded = data[:-pad_len]
        self.__notify_process("移除PKCS#5填充", f"移除 {pad_len} 字节填充, 原始长度: {len(unpadded)}字节")
        return unpadded

    def encrypt(self, data):
        """
        加密数据，使用CBC模式
        :param data: 需要加密的数据(bytes)
        :return: (iv + 加密后的数据, 加密时间)
        """
        # 生成随机IV
        iv = os.urandom(8)
        self.__notify_process("开始加密", f"数据长度: {len(data)}字节, 使用CBC模式")
        self.__notify_process("生成IV", f"IV: {iv.hex()}")
        
        # 记录开始时间
        start_time = time.time()
        
        # 对数据进行填充
        padded_data = self.__pad(data)
        
        # 分块加密
        result = bytearray()
        prev_block = iv  # 第一块使用IV作为前一个密文块
        
        total_blocks = len(padded_data) // self.block_size
        self.__notify_process("CBC模式加密", f"共 {total_blocks} 个块")
        
        for i in range(0, len(padded_data), self.block_size):
            # 获取当前块
            block = padded_data[i:i+self.block_size]
            block_num = i // self.block_size + 1
            
            self.__notify_process(f"处理块 #{block_num}/{total_blocks}", f"块大小: {len(block)}字节")
            
            # CBC模式：当前明文块与前一个密文块进行异或
            xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
            self.__notify_process(f"CBC异或 #{block_num}", f"明文块 XOR 前一密文块")
            
            # 加密
            encrypted_block = self.__des_encrypt_block(xored_block)
            
            # 保存加密结果
            result.extend(encrypted_block)
            
            # 更新前一个密文块
            prev_block = encrypted_block
            
            self.__notify_process(f"块 #{block_num} 加密完成", f"输出长度: {len(encrypted_block)}字节")
        
        # 计算加密时间
        encryption_time = time.time() - start_time
        
        output = bytes(iv + result)
        self.__notify_process("加密完成", f"总耗时: {encryption_time:.6f}秒, 输出长度: {len(output)}字节")
        
        # 返回IV + 加密数据以及加密时间
        return output, encryption_time

    def decrypt(self, data):
        """
        解密数据，使用CBC模式
        :param data: 加密后的数据，包含IV(前8字节)
        :return: (解密后的数据, 解密时间)
        """
        # 提取IV和加密数据
        iv = data[:8]
        encrypted_data = data[8:]
        
        self.__notify_process("开始解密", f"数据长度: {len(data)}字节, 使用CBC模式")
        self.__notify_process("提取IV", f"IV: {iv.hex()}")
        
        # 记录开始时间
        start_time = time.time()
        
        # 分块解密
        result = bytearray()
        prev_block = iv  # 第一块使用IV作为前一个密文块
        
        total_blocks = len(encrypted_data) // self.block_size
        self.__notify_process("CBC模式解密", f"共 {total_blocks} 个块")
        
        for i in range(0, len(encrypted_data), self.block_size):
            # 获取当前密文块
            block = encrypted_data[i:i+self.block_size]
            block_num = i // self.block_size + 1
            
            self.__notify_process(f"处理块 #{block_num}/{total_blocks}", f"块大小: {len(block)}字节")
            
            # 解密
            decrypted_block = self.__des_encrypt_block(block, decrypt=True)
            
            # CBC模式：解密结果与前一个密文块进行异或
            xored_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            self.__notify_process(f"CBC异或 #{block_num}", f"解密结果 XOR 前一密文块")
            
            # 保存解密结果
            result.extend(xored_block)
            
            # 更新前一个密文块
            prev_block = block
            
            self.__notify_process(f"块 #{block_num} 解密完成", f"输出长度: {len(xored_block)}字节")
        
        # 去除填充
        try:
            unpadded_data = self.__unpad(result)
            if unpadded_data is None:
                self.__notify_process("解密失败", "无效的PKCS#5填充")
                raise ValueError("Invalid padding")
        except Exception as e:
            # 如果解密过程出错，返回None
            self.__notify_process("解密错误", f"错误: {str(e)}")
            unpadded_data = None
        
        # 计算解密时间
        decryption_time = time.time() - start_time
        
        if unpadded_data is not None:
            self.__notify_process("解密完成", f"总耗时: {decryption_time:.6f}秒, 输出长度: {len(unpadded_data)}字节")
        
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