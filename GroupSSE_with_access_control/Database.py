import nltk
import os
import random
import crypto
import DiffieHellman as DH


def create_database(file_dir):
    db = database()
    db.scan_dir(file_dir)
    return db


class database:
    def __init__(self):
        self.db = []#数据库存储，本质是正排索引，服务器存储一个文件名和对应的关键词
        self.word_list = []#关键词列表，给出所有包含在数据库中的关键词
        self.dic = {}#目录，也就是倒排索引，根据关键词存储文件id
        self.file_list = []#文件目录，存储着所有文件名

    def preprocess_file(self, filename):#文件的预处理，结果会返回文件的关键词
        file = open(filename, "r")
        words = []
        for line in file:
            line = line.split()
            words.append(line[0])
        return words

    def addfile(self, filename):
        self.file_list.append(filename)
        pair = [filename, self.preprocess_file(filename)]
        self.db.append(pair)
        words = self.preprocess_file(filename)  #合并关键词集合，便于之后构建TSet倒排索引
        for word in words:
            if word in self.dic:
                self.dic[word].append(filename)
            else:
                self.word_list.append(word)
                self.dic[word] = [filename]

    def scan_dir(self, file_dir):
        for root, dirs, files in os.walk(file_dir):
            for file in files:
                if file.endswith(".txt"):
                    print(file)
                    self.addfile(file_dir + "/" + file)

    def get_file_index(self, file):
        return self.file_list.index(file)


def test_ddh(c):
    secure_random = random.SystemRandom()
    file = secure_random.choice(c.file_list)
    print(file)
    k_i = os.urandom(512)
    ddh = DH.DiffieHellman()
    index = c.get_file_index(file)
    print(index)
    x_ind = ddh.genPrivateKey(k_i, str(index))
    print(len(bin(x_ind)))


def test_k_e(c):
    secure_random = random.SystemRandom()
    word = c.word_list[1]
    print(word)
    array = [file for file in c.dic[word]]
    file = secure_random.choice(array)
    k_s = os.urandom(512)
    k_e = crypto.prf_256(k_s, word)
    ddh = DH.DiffieHellman()
    index = c.get_file_index(file)
    print(index)
    e = crypto.enc(k_e, os.urandom(16), str(index))
    print(e)


if __name__ == '__main__':
    c = create_database('./RandomTest')
    print(c.db)
    print(len(c.word_list), c.word_list)
    print(c.file_list)
    print(len(c.dic), c.dic)
    test_k_e(c)

