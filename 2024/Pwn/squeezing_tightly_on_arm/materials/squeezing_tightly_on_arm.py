import sys
version = sys.version_info
del sys

FLAG = 'TBTL{3SC4P1NG_FR0M_PYTH0N_15_N0T_4N_345Y_T45K}'
del FLAG


def check(command):

    if len(command) > 120:
        return False

    allowed = {
        "'": 0,
        '.': 1,
        '(': 1,
        ')': 1,
        '/': 1,
        '+': 1,
        }

    for char, count in allowed.items():
        if command.count(char) > count:
            return False

    return True


def safe_eval(command, loc={}):

    if not check(command):
        return

    return eval(command, {'__builtins__': {}}, loc)


for _ in range(10):
    command = input(">>> ")

    if command == 'version':
        print(str(version))
    else:
        safe_eval(command)
