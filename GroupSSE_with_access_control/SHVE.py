"""
一个简易的modified SHVE实现，以及bloom filter的实现
测试，在bf2包含bf1的时候能得到正确的message，但不包含的话，程序会发生错误，应该是解密出的东西根本不能拿来当作密钥吧......倒也确实和预期的效果差不多就是了
需要注意，由于我们将添加值作为计算的一部分，它将无法处理冲突的问题，因为一旦两个hash结果是同一个位置，那将无法得到准确的结果（因为一旦冲突了，下一次结果会覆盖上一次的结果，这样计算结果就不对了）
考虑使用布谷鸟过滤器，降低冲突带来的影响（如果还不行那就只有在选择token的时候尽力选择了）
"""
import os
import random
import mmh3
import crypto
import DiffieHellman as DH
import Read_data
import keys


class BloomFilter:
    def __init__(self, capacity, functions):#capacity表示bloom filter容量，functions表示哈希函数的个数
        self.capacity = capacity
        self.bit_array = [0 for i in range(self.capacity)]
        self.counts = functions

    def _handle_position(self, element):#获取哈希结果和位置
        position_list = []
        for i in range(self.counts):
            hash_value = mmh3.hash(element, i)
            value = hash_value % self.capacity
            position_list.append((hash_value, value))

        return position_list

    def add(self, element):#添加元素
        position_list = self._handle_position(element)
        for position in position_list:
            self.bit_array[position[1]] = position[0]

        return position_list

    def existence(self, element):#检查元素是否存在
        position_list = self._handle_position(element)

        result = True
        for position in position_list:
            result = self.bit_array[position[1]] and result

        return result

    def to_number1(self):#返回bloom filter中不为0的位数
        number_1 = 0
        for i in range(self.capacity):
            if self.bit_array[i] != 0:
                number_1 += 1

        return number_1


def shve_result_trans(shve_result):#用于将SHVE解密的结果转换为可计算的整数
    result = shve_result.decode()
    result = result.replace(',', ' ').split()

    return int(result[0]), int(result[1])


class modified_SHVE:
    def __init__(self):
        self.msk = keys.msk
        self.ddh = DH.DiffieHellman()
        self.K = random.getrandbits(256)
        self.iv = keys.iv

    def keygen(self, bf1, message):#根据owner上传的bf1加密相应的message
        s = []
        value = 0
        for i in bf1:
            if i != 0:
                index = bf1.index(i)
                s.append(index)
                value = self.ddh.genPrivateKey(self.msk, str(i) + str(index)) ^ value

        d_0 = value ^ self.K
        d_1 = crypto.enc(self.K.to_bytes(32, 'big'), self.iv, str(message))

        return d_0, d_1, s

    def enc(self, bf2):#根据user上传的bf2获得加密结果
        c = []
        for i in range(len(bf2)):
            val = self.ddh.genPrivateKey(self.msk, str(bf2[i]) + str(i))
            c.append((val, i))

        return c

    def query(self, S, C):#仅在bf2包含bf1的情况下才有结果，否则返回false
        value = 0
        for i in S[2]:
            value = value ^ C[i][0]
        K = S[0] ^ value

        try:
            message = crypto.dec(K.to_bytes(32, 'big'), self.iv, S[1])
        except ValueError:
            return False
        else:
            return shve_result_trans(message)


class modified_SHVE_search:#owner和user的密钥还不一样，不也挺好的吗？这还得再整一个类
    def __init__(self):
        param = Read_data.read_shve_Param()
        self.msk = keys.msk
        self.ddh = DH.DiffieHellman__(param[0], param[1], param[2])
        self.K = random.getrandbits(256)
        self.iv = keys.iv

    def keygen(self, bf1, message):#根据owner上传的bf1加密相应的message
        s = []
        value = 0
        for i in bf1:
            if i != 0:
                index = bf1.index(i)
                s.append(index)
                value = self.ddh.genPrivateKey(self.msk, str(i) + str(index)) ^ value

        d_0 = value ^ self.K
        d_1 = crypto.enc(self.K.to_bytes(32, 'big'), self.iv, str(message))

        return d_0, d_1, s

    def enc(self, bf2):#根据user上传的bf2获得加密结果
        c = []
        for i in range(len(bf2)):
            val = self.ddh.genPrivateKey(self.msk, str(bf2[i]) + str(i))
            c.append((val, i))

        return c

    def query(self, S, C):#仅在bf2包含bf1的情况下才有结果，否则返回false
        value = 0
        for i in S[2]:
            value = value ^ C[i][0]
        K = S[0] ^ value

        try:
            message = crypto.dec(K.to_bytes(32, 'big'), self.iv, S[1])
        except ValueError:
            return False
        else:
            return shve_result_trans(message)


if __name__ == '__main__':
    TSet = Read_data.read_TSet()
    a = random.sample(TSet.keys(), 1)
    b = TSet[a[0]]
    print(a, TSet[a[0]])

    bf1 = BloomFilter(200, 4)
    bf1.add('token1')
    SHVE = modified_SHVE()
    access_array = SHVE.keygen(bf1.bit_array, str(b[0]) + ',' + str(b[1]))
    print(bf1.to_number1(), bf1.bit_array)
    print(access_array)
    bf2 = BloomFilter(200, 4)
    #bf2.add('token1')
    bf2.add('token2_')
    bf2.add('token3')
    bf2.add('token4')
    bf2.add('token5')
    bf2.add('token6')
    bf2.add('token7')
    search_array = SHVE.enc(bf2.bit_array)
    print(bf2.to_number1(), search_array)
    result = SHVE.query(access_array, search_array)
    if result:
        print(result)
    else:
        print('ValueError!This query is wrong!')


