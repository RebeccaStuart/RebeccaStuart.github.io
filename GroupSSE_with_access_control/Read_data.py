def read_TSet():
    TSet = {}
    file = open('./Enc_database/TSet.txt', 'r')
    for line in file:
        line = line.split()
        TSet[int(line[0])] = (int(line[1]), int(line[2]))

    return TSet


def read_XSet():
    XSet = []
    file = open('./Enc_database/XSet.txt', 'r')
    for line in file:
        line = line.split()
        XSet.append(int(line[0]))

    return XSet


def read_Counter():
    Counter = {}
    file = open('./UserData/Counter.txt', 'r')
    for line in file:
        line = line.split()
        Counter[line[0]] = int(line[1])

    return Counter


def read_Keys():#这个函数实际上可以作废了，因为那些个密钥一用成字符串格式就无法加密解密了
    client_key = {}
    file = open('./UserData/Keys.txt', 'r')
    for line in file:
        line = line.split()
        client_key[line[0]] = line[1]

    return client_key


def read_Param():
    param = []
    file = open('./UserData/Param.txt', 'r')
    for line in file:
        line = line.split()
        for val in line:
            param.append(int(val))

    return param


def read_shve_Param():
    shve_param = []
    file = open('./UserData/shve_Param.txt', 'r')
    for line in file:
        line = line.split()
        for val in line:
            shve_param.append(int(val))

    return shve_param


def read_data():#依次返回TSet、XSet、Counter、用户密钥、ddh参数
    return read_TSet(), read_XSet(), read_Counter(), read_Keys(), read_Param(), read_shve_Param()


if __name__ == '__main__':
    result = read_Keys()['k_t']
    print(type(result), result)
    print(type(result.encode()), result.encode())
