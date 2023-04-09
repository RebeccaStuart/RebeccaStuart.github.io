#在我们这个多用户的体系下，显然是用户交付密钥
import keys
import crypto
import random
import Database as db
import os
import DiffieHellman as DH
import SHVE
import time


secure_random = random.SystemRandom()
Counter = {}

class setup:
    def __init__(self):
        self.ddh = DH.DiffieHellman()
        self.shve = SHVE.modified_SHVE()
        k_t = keys.k_t
        k_y = keys.k_y  # for producing private key
        k_x = keys.k_x  # for producing private key
        k_z = keys.k_z  # for producing private key
        self.client_key = {"k_x": k_x, "k_y": k_y, "k_z": k_z, "k_t": k_t}

    def access_control(self, bf1, message):
        return self.shve.keygen(bf1, str(message[0]) + ',' + str(message[1]))

    def encrypted_database(self, database, bf1):
        k_x = self.client_key["k_x"]
        k_y = self.client_key["k_y"]
        k_z = self.client_key["k_z"]
        k_t = self.client_key["k_t"]

        XSet = []
        T = {}
        dictionary = database.dic

        for word in dictionary:
            array = [file for file in dictionary[word]]
            if word not in Counter:
                Counter[word] = 0

            while len(array):
                file = secure_random.choice(array)
                array.remove(file)
                index = database.get_file_index(file)
                address = self.ddh.genPrivateKey(k_t, word + str(Counter[word]) + '0')
                val_ = self.ddh.genPrivateKey(k_t, word + str(Counter[word]) + '1')#用于计算val值
                val = val_ ^ index #异或得到val值

                z = self.ddh.genPrivateKey(k_z, word + str(Counter[word]))
                z_inv = crypto.mod_inv(z, self.ddh.prime)
                y = self.ddh.genPrivateKey(k_y, str(index))
                a = (y * z_inv) % self.ddh.prime

                T[address] = self.access_control(bf1, (val, a))

                xtag_1 = self.ddh.genPrivateKey(k_x, word)
                xtag_2 = y
                xtag_3 = self.ddh.genPublicKey(xtag_1)
                xtag = self.ddh.genSecret(xtag_2, xtag_3)#genSecret这个函数巨坑，它是以后一个参数作为基数，前一个参数作为指数来算的......
                XSet.append(xtag)

                Counter[word] = Counter[word] + 1

        file = open('./UserData/Keys.txt', 'w')
        for key in self.client_key:
            file.write('{}  {}\n'.format(key, self.client_key[key]))
        print(type(self.client_key["k_t"]), self.client_key["k_t"])
        file.close()

        return T, XSet, self.ddh, self.shve


def main():
    database = db.create_database('./RandomTest')
    print(database.db)
    print(len(database.word_list), database.word_list)
    print(database.file_list)
    print(len(database.dic), database.dic)

    bloom_filter_1 = SHVE.BloomFilter(200, 4)
    for i in range(0, 2):
        bloom_filter_1.add(keys.tokens[i])
    enc_database = setup()
    ODXT = enc_database.encrypted_database(database, bloom_filter_1.bit_array)
    print(ODXT[0])

    file = open('./Enc_database/TSet_with_access_control.py', 'w')
    file.write('TSet = {}'.format(ODXT[0]))
    file.close()

    file = open('./Enc_database/XSet.txt', 'w')
    for xtag in ODXT[1]:
        file.write('{}\n'.format(xtag))
    file.close()

    file = open('./UserData/Param.txt', 'w')
    file.write('{}   {}   {}'.format(ODXT[2].prime, ODXT[2].prime_p, ODXT[2].generator))
    file.close()

    file = open('./UserData/shve_Param.txt', 'w')
    file.write('{}   {}   {}'.format(ODXT[3].ddh.prime, ODXT[3].ddh.prime_p, ODXT[3].ddh.generator))
    file.close()

    print(Counter)
    file = open('./UserData/Counter.txt', 'w')
    for word in Counter:
        file.write('{}  {}\n'.format(word, Counter[word]))
    file.close()


if __name__ == '__main__':
    main()


