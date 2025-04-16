import random
import hashlib

class DiffieHellman:
    """
    Diffie-Hellman密钥交换算法的实现
    """
    
    def __init__(self, prime=None, generator=None):
        """
        初始化Diffie-Hellman
        :param prime: 大质数p (如果为None，使用预定义的安全质数)
        :param generator: 生成元g (如果为None，使用预定义的生成元)
        """
        # 如果没有指定，使用预定义的安全质数和生成元
        if prime is None or generator is None:
            # 使用一个已知的安全质数和对应的生成元
            # 这是一个2048位的安全质数（MODP组14）
            self.prime = int(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
            self.generator = 2
        else:
            self.prime = prime
            self.generator = generator
            
        # 生成私钥 (1 < private_key < prime-1)
        self.private_key = random.randint(2, self.prime - 2)
        print(f'私钥：{self.private_key}')
        # 计算公钥: public_key = generator^private_key mod prime
        self.public_key = pow(self.generator, self.private_key, self.prime)
        print(f'公钥：{self.public_key}')

    def generate_shared_secret(self, other_public_key):
        """
        使用对方的公钥生成共享密钥
        :param other_public_key: 对方的公钥
        :return: 共享密钥
        """
        # 计算共享密钥: shared_secret = other_public_key^private_key mod prime
        shared_secret = pow(other_public_key, self.private_key, self.prime)
        
        # 将共享密钥转换为DES需要的8字节密钥
        # 由于共享密钥可能很大，我们使用哈希函数将其处理为固定长度
        # 然后截取前8字节作为DES密钥
        hash_obj = hashlib.sha256(str(shared_secret).encode())
        return hash_obj.digest()[:8]  # 截取前8字节作为DES密钥
    
    def get_public_key(self):
        """
        获取公钥
        :return: 公钥
        """
        return self.public_key 