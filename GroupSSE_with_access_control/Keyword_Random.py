#该文件用于产生测试用的随机关键词和随机文件
from random_words import RandomWords
import random
import numpy as np
import os

def Keywords_gen(f_number, k_number):
    words = []
    new_words = []
    for i in range(200):
        while True:
            r = RandomWords()
            rw = r.random_words()
            if rw[0] in words:
                continue
            words.append(rw[0])
            break

    #file = open('./RandomTest/Keywords.txt', 'w')
    for word in words:
        new_words.append(word.lower())
        #file.write(word.lower() + ' ')


    W = []
    for i in range(f_number):
        W.append(random.sample(range(1, len(new_words)), k_number))

    for i in range(f_number):
        name = './RandomTest/Enc_test_10/%02d.txt' % (i + 1)
        file = open(name, 'w')
        for j in range(k_number):
            file.write(str(words[W[i][j]]) + '\n')
        file.close()


if __name__ == '__main__':
    m = 10#文件个数
    n = 10#关键词个数
    Keywords_gen(m, n)
