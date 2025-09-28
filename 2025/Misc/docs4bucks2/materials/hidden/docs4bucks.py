#!/usr/bin/env python3
import base64
import time
import subprocess
import sys
import tempfile
import shutil
import os

BANNER = r"""
 _______                                       __    __        _______                       __
|       \                                     |  \  |  \      |       \                     |  \
| $$$$$$$\  ______    _______   _______       | $$  | $$      | $$$$$$$\ __    __   _______ | $$   __   _______
| $$  | $$ /      \  /       \ /       \      | $$__| $$      | $$__/ $$|  \  |  \ /       \| $$  /  \ /       \\
| $$  | $$|  $$$$$$\|  $$$$$$$|  $$$$$$$      | $$    $$      | $$    $$| $$  | $$|  $$$$$$$| $$_/  $$|  $$$$$$$\
| $$  | $$| $$  | $$| $$       \$$    \        \$$$$$$$$      | $$$$$$$\| $$  | $$| $$      | $$   $$  \$$    \
| $$__/ $$| $$__/ $$| $$_____  _\$$$$$$\            | $$      | $$__/ $$| $$__/ $$| $$_____ | $$$$$$\  _\$$$$$$\\
| $$    $$ \$$    $$ \$$     \|       $$            | $$      | $$    $$ \$$    $$ \$$     \| $$  \$$\|       $$
 \$$$$$$$   \$$$$$$   \$$$$$$$ \$$$$$$$              \$$       \$$$$$$$   \$$$$$$   \$$$$$$$ \$$   \$$ \$$$$$$$
"""

def slow_print(s, baud_rate=0):
    for letter in s:
        sys.stdout.write(letter)
        sys.stdout.flush()
        time.sleep(baud_rate)


def hack_detected():
    slow_print("H4cking attempt detected...\n")
    slow_print("No $$$ for you!!\n")
    sys.exit(1)


def validate(code, documented_code):
    code_lines = code.split("\n")
    doc_lines = documented_code.split("\n")
    idx = 0
    added = []
    for line in doc_lines:
        if idx < len(code_lines) and line == code_lines[idx]:
            idx += 1
        else:
            added.append(line)
    if idx != len(code_lines):
        hack_detected()
    # Only allow added comment lines composed of ASCII-printable characters
    for line in added:
        if (not line.strip().startswith("#")) or any(ord(ch) < 32 or ord(ch) > 126 for ch in line):
            hack_detected()


def run_tests(documented_code):
    # Run tests on a temporary copy so we don't overwrite originals
    tempdir = tempfile.mkdtemp(prefix='doc4bucks_')
    try:
        # Prepare flag_checker.py
        fc_path = os.path.join(tempdir, 'flag_checker.py')
        with open(fc_path, 'w') as f:
            f.write(documented_code)
        # Copy resources directory
        orig_res = os.path.join(os.getcwd(), 'resources')
        if os.path.isdir(orig_res):
            shutil.copytree(orig_res, os.path.join(tempdir, 'resources'))
        # Invoke pytest in tempdir
        result = subprocess.run(
            ['pytest', '-q', 'flag_checker.py'],
            cwd=tempdir,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        if result.returncode != 0:
            sys.exit(1)
    finally:
        shutil.rmtree(tempdir)


def main():
    print(BANNER)
    slow_print("Welcome to Docs 4 Bucks -- You document our code, we give you $$$!!!!\n")
    slow_print("\nRULES:\n")
    slow_print("  1. Don't delete or change any existing line of code!\n")
    slow_print("  2. You may only add documentation (lines starting with '#' containing ascii printable characters).\n")
    slow_print("  3. Hacking is futile, we have world-class protection in place.\n\n")
    slow_print("Your job is to document our flag_checker.py (base64):\n\n")

    # read original library
    orig_path = os.path.join(os.getcwd(), 'flag_checker.py')
    code = open(orig_path).read()
    print(base64.b64encode(code.encode('utf-8')).decode('utf-8'))

    slow_print("\nSubmit documented version of the code (base64):\n\n")
    inp = input()
    try:
        doc_code = base64.b64decode(inp).decode('utf-8')
    except Exception:
        hack_detected()

    validate(code, doc_code)

    slow_print("Thank you for your contribution, we'll run the test suite just to be safe...\n\n")
    run_tests(doc_code)

    slow_print("\nOur engineers will review your submission and we'll let you know if your contribution is $$$ worthy\n")

if __name__ == '__main__':
    main()
