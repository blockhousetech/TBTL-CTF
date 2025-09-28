#!/usr/bin/env python3

import sys
import signal

GREETING = """
 ▒█████    ██████  ██▓ ███▄    █ ▄▄▄█████▓   ▓█████ ▒██   ██▒ ▄▄▄       ███▄ ▄███▓
▒██▒  ██▒▒██    ▒ ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒   ▓█   ▀ ▒▒ █ █ ▒░▒████▄    ▓██▒▀█▀ ██▒
▒██░  ██▒░ ▓██▄   ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░   ▒███   ░░  █   ░▒██  ▀█▄  ▓██    ▓██░
▒██   ██░  ▒   ██▒░██░▓██▒  ▐▌██▒░ ▓██▓ ░    ▒▓█  ▄  ░ █ █ ▒ ░██▄▄▄▄██ ▒██    ▒██
░ ████▓▒░▒██████▒▒░██░▒██░   ▓██░  ▒██▒ ░    ░▒████▒▒██▒ ▒██▒ ▓█   ▓██▒▒██▒   ░██▒
░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ▒ ▒   ▒ ░░      ░░ ▒░ ░▒▒ ░ ░▓ ░ ▒▒   ▓▒█░░ ▒░   ░  ░
  ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░░ ░░   ░ ▒░    ░        ░ ░  ░░░   ░▒ ░  ▒   ▒▒ ░░  ░      ░
░ ░ ░ ▒  ░  ░  ░   ▒ ░   ░   ░ ░   ░            ░    ░    ░    ░   ▒   ░      ░
    ░ ░        ░   ░           ░                ░  ░ ░    ░        ░  ░       ░

         Instructions:
           1) Use your st4lk1ng skillz
           2) Get the FLAG

"""

QUESTIONS = [
    ("1) One of our branch headquarters is located @ <location_1.png>. What is the full name of that coworking space and who is the managing director of that branch?\n\nFormat: <name_of_coworking_space> <managing_director_name> <managing_director_surname>\n", ["Luxembourg House of Financial Technology Petra Krizan"]),

    ("2) One of our branch headquarters is located @ <location_2.png>. What is the full address of that building?\n\nFormat: <house_number> <street_name> <town> <postcode> <country>\n", ["2 Staverton Road Oxford OX2 6XJ United Kingdom", "2 Staverton Road Oxford OX26XJ United Kingdom", "2 Staverton Road Oxford OX2 6XJ UK", "2 Staverton Road Oxford OX26XJ UK"]),

    ("3) Our branch with the best BBQ is located @ <location_3.png>. What is the full address of that building?\n\nFormat: <street_name> <house number> <postcode> <town> <country>\n", ["Koturaska 51 10000 Zagreb Croatia"]),

    ("4) Two of our team members ran a road race together earlier this year @ <location_4.png>. What city was the race at and what were their finish times (hh:mm:ss)?\n\nFormat: <city> <slower_result> <faster_result>\n", ["Manchester 00:53:04 00:49:12"]),

    ("5) The squad from our Zagreb office took part in a local charity futsal tournament in 2024 @ <location_5.png>. What was the tournament called and what place did they win?\n\n Format: <tournament_name> <place_won>\n", ["Kopacka solidarnosti 3", "Kopacka solidarnosti third"]),

    ("6) One of our senior members has an artistic side to them as you can see from the beautiful flower @ <location_6.png>. What is the name of the book with that member's self-portrait on its cover? \n\n Format: <book title>\n", ["Concurrency, Security, and Puzzles"]),
]

FLAG = "FortID{C3rt1fi3d_0p3n_50urc3_1n73l1genc3_M45t3r}"


def timeout_handler(signum, frame):
    print("\nSession timed out! Please try again.")
    sys.exit(1)


def main():
    signal.signal(signal.SIGALRM, timeout_handler)

    print(GREETING)

    for question, answers in QUESTIONS:
        print("\n" +"="*60 + "\n")
        print(question)
        try:
            response = input("Answer: ").strip().lower()
        except EOFError:
            return

        if response not in [ans.lower() for ans in answers]:
            print("\nTry harder!")
            return

    print(f"\nCongratulations!\nYou passed the exam, here is your certificate: {FLAG}")


if __name__ == "__main__":
    main()
