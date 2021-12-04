import hashlib
import random
from math import gcd
from random import choice
from string import ascii_lowercase


def Eratosphen():
    n = 20000
    arr_nums = []
    for i in range(n + 1):
        arr_nums.append(i)
    arr_nums[1] = 0
    i = 2
    while i ** 2 <= n:
        if arr_nums[i] != 0:
            j = i ** 2
            while j < n:
                arr_nums[j] = 0
                j += i
        i += 1
    arr_nums = set(arr_nums)
    arr_nums.remove(0)
    arr_nums = list(arr_nums)
    arr_nums.sort()
    print(f"Массив простых чисел: {arr_nums}\nДлина массива: {len(arr_nums)}")
    q_index = random.randint(500, 1000)
    q = arr_nums[q_index]
    while True:
        N = 2 * q + 1
        if N not in arr_nums:
            q_index = random.randint(500, 1000)
            q = arr_nums[q_index]
            continue
        else:
            break
    return q, N


def generator_module_N(N):  # для любого 0 < X < N существует и единственный x такой, что g^x % N = X
    first_set = set()
    second_set = set()
    for num in range(1, N):
        if gcd(num, N) == 1:
            first_set.add(num)

    for g in range(1, N):
        for x in range(1, N):
            second_set.add(pow(g, x) % N)

        if first_set == second_set:
            return g


def SRP_encryption():
    I = "Tatiana"
    password = "Привет, SRP!"

    k = 3
    q, N = Eratosphen()
    g = generator_module_N(N)
    print(f'\t\n {N = }\t\n {q = }\t\n {k = }\t\n {g = }\t\n {password = }')

    print("\nРегистрация.")
    print("\tКлиент генерирует:")

    s = ''.join(choice(ascii_lowercase) for i in range(16))  # случайная строка(соль)
    print(f'\t{s = }')

    x = int(hashlib.sha512(s.encode() + password.encode()).hexdigest(), 16)  # x = H(s, p)
    print(f'\t{x = }')

    v = pow(g, x, N)  # v = g^x % N
    print(f'\t{v = }')

    print("\t\n и присылает серверу три поля:")
    print(f'\t{I = }')
    print(f'\t{s = }')
    print(f'\t{v = }')

    print("\nАутентификация.")
    print("\tКлиент передаёт пару из логина I и вычисленного A:")

    a = random.randint(2, 100)
    A = pow(g, a, N)  # A = g^a % N
    print(f'\t\n {A = }\t\n {I = }')

    print('\t\nСервер должен убедиться, что A != 0')
    if A != 0:

        print("\t\nСервер генерирует случайное число b и вычисляет B")

        b = random.randint(2, 100)
        print(f'\t{b = }')

        B = (k * v + pow(g, b, N)) % N  # B = (k*v + g^b % N) % N
        print(f'\t{B = }')

        print("\tи отсылает клиенту s(соль) и вычисленное B")

        print("\t\nКлиент проверяет, что B != 0")
        if B != 0:
            print("\t\nЗатем обе стороны вычисляют скремблер: U = H(A, B)")

            U = int(hashlib.sha512(str(A).encode() + str(B).encode()).hexdigest(), 16)
            print(f'\t{U = }')

            print("\t\nЕсли U = 0, то соединение прерывается")
            if U != 0:
                print("\t\nКлиент и сервер вычисляют общий ключ сессии")
                # x = H(s, p) - вычислялся клиентом при регистрации
                client_S = pow((B - k*(pow(g, x, N))), (a + U * x), N)  # S = ((B - k*(g^x % N)) ^ (a + U*x)) % N
                print(f'\t{client_S = }')

                client_Key = int(hashlib.sha512(str(client_S).encode()).hexdigest(), 16)  # хэширование S
                print(f'\t{client_Key = }')

                server_S = pow(A * pow(v, U, N), b, N)  # S = ((A*(v^U % N)) ^ b) % N
                print(f'\t{server_S = }')

                server_Key = int(hashlib.sha512(str(server_S).encode()).hexdigest(), 16)
                print(f'\t{server_Key = }')

                if server_Key == client_Key:
                    print("\t\tКлючи клиента и сервера совпадают!")
                else:
                    print("\t\tОшибка: Ключи клиента и сервера НЕ СОВПАЛИ")

                print("\t---------Проверка сервера клиентом--------")
                print("\tКлиент вычисляет М и отсылает серверу.")  # M = H( H(N) XOR H(g), H(I), s, A, B, K)

                HN = int(hashlib.sha512(str(N).encode()).hexdigest(), 16)
                Hg = int(hashlib.sha512(str(g).encode()).hexdigest(), 16)
                HI = int(hashlib.sha512(str(I).encode()).hexdigest(), 16)

                client_M = int(hashlib.sha512(str(HN ^ Hg).encode() + str(HI).encode() + str(client_S).encode() + str(A).encode() + str(B).encode() + str(k).encode()).hexdigest(), 16)
                print(f'\t{client_M = }')

                print("\tСервер у себя вычисляет M используя свою копию ключа, и проверяет равенство")
                server_M = int(hashlib.sha512(str(HN ^ Hg).encode() + str(HI).encode() + str(server_S).encode() + str(A).encode() + str(B).encode() + str(k).encode()).hexdigest(), 16)
                print(f'\t{server_M = }')
                if client_M == server_M:
                    print("\t\tПодтверждено!")
                else:
                    print("\t\tНЕ подтверждено!")

                print("\t---------Проверка клиента сервером--------")

                client_R = int(hashlib.sha512(str(A).encode() + str(client_M).encode() + str(client_Key).encode()).hexdigest(), 16)
                print(f'\t{client_R = }')

                server_R = int(hashlib.sha512(str(A).encode() + str(server_M).encode() + str(server_Key).encode()).hexdigest(), 16)
                print(f'\t{server_R = }')
                if client_R == server_R:
                    print("\t\tПодтверждено!")
                else:
                    print("\t\tНЕ подтверждено!")

            else:
                print("ОШИБКА СОЕДИНЕНИЯ: U = 0!")
        else:
            print("ОШИБКА СОЕДИНЕНИЯ: B = 0")
    else:
        print("ОШИБКА СОЕДИНЕНИЯ: A = 0")


if __name__ == "__main__":

    SRP_encryption()