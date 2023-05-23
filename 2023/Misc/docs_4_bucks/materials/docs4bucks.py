import base64
import time
import subprocess
import sys


BANNER = (" _______                                       __    __        _______                       __                 \n"
          "|       \                                     |  \  |  \      |       \                     |  \                \n"
          "| $$$$$$$\  ______    _______   _______       | $$  | $$      | $$$$$$$\ __    __   _______ | $$   __   _______ \n"
          "| $$  | $$ /      \  /       \ /       \      | $$__| $$      | $$__/ $$|  \  |  \ /       \| $$  /  \ /       \\\n"
          "| $$  | $$|  $$$$$$\|  $$$$$$$|  $$$$$$$      | $$    $$      | $$    $$| $$  | $$|  $$$$$$$| $$_/  $$|  $$$$$$$\n"
          "| $$  | $$| $$  | $$| $$       \$$    \        \$$$$$$$$      | $$$$$$$\| $$  | $$| $$      | $$   $$  \$$    \ \n"
          "| $$__/ $$| $$__/ $$| $$_____  _\$$$$$$\            | $$      | $$__/ $$| $$__/ $$| $$_____ | $$$$$$\  _\$$$$$$\\\n"
          "| $$    $$ \$$    $$ \$$     \|       $$            | $$      | $$    $$ \$$    $$ \$$     \| $$  \$$\|       $$\n"
          " \$$$$$$$   \$$$$$$   \$$$$$$$ \$$$$$$$              \$$       \$$$$$$$   \$$$$$$   \$$$$$$$ \$$   \$$ \$$$$$$$ \n"
          "                                                                                                                \n")


def slow_print(s, baud_rate=0):
    for letter in s:
        sys.stdout.write(letter)
        sys.stdout.flush()
        time.sleep(baud_rate)


def hack_detected():
    slow_print("H4cking attempt detected...\n")
    slow_print("No $$$ for you!!\n")
    exit(1)


def validate(code, documented_code):
    code_lines = code.split("\n")
    documented_code_lines = documented_code.split("\n")

    c_line_id = 0
    added_lines = []
    for dc_line in documented_code_lines:
        if c_line_id >= len(code_lines) or dc_line != code_lines[c_line_id]:
            added_lines.append(dc_line)
        else:
            c_line_id += 1

    if c_line_id != len(code_lines):
        hack_detected()

    for line in added_lines:
        if not line.strip().startswith("//") or '`' in line:
            hack_detected()


def run_tests(code):
    f = open("flag-checker/src/lib.rs", "w")
    f.write(code)
    f.close()

    testCommand = ("cd flag-checker; "
                   "cargo t;"
                   "cd ..")

    subprocess.run(testCommand, shell=True)


def main():
    print(BANNER)
    slow_print(
        "Welcome to Docs 4 Bucks -- You document our code, we give you $$$!!!!\n")
    slow_print("\n")
    slow_print("RULES:\n")
    slow_print("  1. Don't delete or change any existing line of code!\n")
    slow_print("  2. You may only add documentation (lines starting with '//').\n")
    slow_print("  3. Hacking is futile, we have world-class protection in place.\n")
    slow_print("\n" * 2)
    slow_print("Your job is to document our flag-checker library (base64):")
    slow_print("\n" * 2)

    code = ''.join(open("original_lib.rs").readlines())
    print(base64.b64encode(code.encode('utf-8')).decode('utf-8'))

    slow_print("\nSubmit documented version of the code (base64):\n\n")

    documented_code_base64 = input()
    documented_code = base64.b64decode(
        documented_code_base64.encode('utf-8')).decode('utf-8')

    print("")

    validate(code, documented_code)

    slow_print(
        "Thank you for your contribution, we'll run the test suite just to be safe...\n\n")

    run_tests(documented_code)

    slow_print(
        "\nOur engineers will review your submission and we'll let you know if your contribution is $$$ worthy\n\n")


if __name__ == '__main__':
    main()
