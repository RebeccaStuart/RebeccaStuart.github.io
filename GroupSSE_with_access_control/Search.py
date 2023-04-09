"""
反正这是做实验，我把随机密钥固定了也没什么问题吧！
"""
import os
import crypto
import DiffieHellman as DH
import Read_data
import keys
from Enc_database import TSet_with_access_control
import SHVE
import time


class client:
    def __init__(self):
        ddh_param = Read_data.read_Param()

        self.shve = SHVE.modified_SHVE_search()
        self.ddh = DH.DiffieHellman__(ddh_param[0], ddh_param[1], ddh_param[2])
        self.Counter = Read_data.read_Counter()
        self.k_x = keys.k_x
        self.k_y = keys.k_y
        self.k_z = keys.k_z
        self.k_t = keys.k_t

    def gen_xtoken(self, words):#w是关键词集合，n代表文件数量，也就是Counter的计数
        if len(words) == 1:
            print(len(words))
            return False

        print(len(words))
        xtoken = [[0 for x in range(len(words) + 1)] for y in range(self.Counter[words[0]])]
        for c in range(self.Counter[words[0]]):
            for i in range(1, len(words)):
                x1 = self.ddh.genPrivateKey(self.k_x, words[i])
                x2 = self.ddh.genPrivateKey(self.k_z, words[0] + str(c))
                x3 = self.ddh.genPublicKey(x2)
                xtoken[c][i] = self.ddh.genSecret(x1, x3)

        return xtoken

    def gen_access_token(self, bf2):
        return self.shve.enc(bf2)

    def search_addr(self, words):
        stag_list = []
        for i in range(self.Counter[words[0]]):
            search_address = self.ddh.genPrivateKey(self.k_t, words[0] + str(i) + '0')
            stag_list.append(search_address)

        return stag_list

    def file_id_dec(self, word, val):
        files = []
        for i in range(len(val)):
            val_ = self.ddh.genPrivateKey(self.k_t, word + str(val[i][0]) + '1')
            id = val[i][1] ^ val_
            files.append(id)

        return files


class server:
    def __init__(self):
        ddh_param = Read_data.read_Param()

        self.shve = SHVE.modified_SHVE_search()
        self.ddh = DH.DiffieHellman__(ddh_param[0], ddh_param[1], ddh_param[2])
        self.TSet = TSet_with_access_control.TSet
        self.XSet = Read_data.read_XSet()

    def xtoken_check(self, c, xtoken, y, n):
        judgement = True
        for j in range(1, n):
            xtag = pow(xtoken[c][j], y, self.ddh.prime_p)
            if xtag in self.XSet:
                judgement = judgement and True
            else:
                judgement = judgement and False

        return judgement

    def access_control_check(self, S, C):
        return self.shve.query(S, C)

    def TSet_check(self, stag, xtoken, n, C):
        enc_files = []
        if not xtoken:
            for i in range(len(stag)):
                if stag[i] in self.TSet:
                    print('Nice!')
                    val = self.TSet[stag[i]]
                    a = self.access_control_check(val, C)
                    if a:
                        enc_files.append((i, a[0]))

            return enc_files

        time_ = 0
        for i in range(len(stag)):
            if stag[i] in self.TSet:
                print('Nice!')
                val = self.TSet[stag[i]]
                a = self.access_control_check(val, C)
                if a:
                    time1 = time.time()
                    temp = self.xtoken_check(i, xtoken, a[1], n)
                    time2 = time.time()
                    if temp:
                        enc_files.append((i, a[0]))
                    time_ = time_ + (time2 -time1)

        print(time_)

        return enc_files


def main():
    words = ['bow', 'gravel', 'problem', 'kill' 'survey']
    client_, server_ = client(), server()
    bf2 = SHVE.BloomFilter(200, 4)
    for i in range(0, 4):
        bf2.add(keys.tokens[i])
    time1 = time.time()
    stag = client_.search_addr(words)
    xtoken = client_.gen_xtoken(words)
    access_token = client_.gen_access_token(bf2.bit_array)
    time2 = time.time()
    search_result = server_.TSet_check(stag, xtoken, len(words), access_token)
    time3 = time.time()
    print(search_result)
    file_id = client_.file_id_dec(words[0], search_result)
    print('搜索结果为:{}, token时间为：{}，搜索时间为：{}'.format(file_id, time2 - time1, time3 - time2))


if __name__ == '__main__':
    main()
