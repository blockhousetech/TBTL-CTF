import os

class FlagChecker:
    def __init__(self, path_to_flag: str):
        self.path_to_flag = path_to_flag

    def check(self) -> bool:
        try:
            with open(self.path_to_flag, 'r') as f:
                flag = f.read()
        except (FileNotFoundError, IOError):
            return False
        return flag.startswith("FortID{") and flag.endswith("}\n")


def test_flag():
    flag_path = os.path.join(os.path.dirname(__file__), 'resources', 'flag.txt')
    checker = FlagChecker(flag_path)
    assert checker.check()


def test_invalid(tmp_path):
    bad_flag = tmp_path / "bad_flag.txt"
    bad_flag.write_text("NOT_A_FLAG\n")
    checker = FlagChecker(str(bad_flag))
    assert not checker.check()


if __name__ == '__main__':
    import pytest
    import sys
    sys.exit(pytest.main([__file__]))
