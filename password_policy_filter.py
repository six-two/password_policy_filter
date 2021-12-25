#!/usr/bin/env python3
import argparse
import sys
from typing import Optional


class SimplePasswordPolicy:
    """
    A simple password policy checker. Works for most policies, such as
    "1 Lowercase, 1 Uppercase, 1 Letter, between 8 and 24 charcters"
    """
    def __init__(self,
                 min_lowercase: int = 0,
                 min_uppercase: int = 0,
                 min_digits: int = 0,
                 min_special: int = 0,
                 min_length: int = 0,
                 max_length: int = 256,
                 allow_unicode: bool = True) -> None:
        self.min_lowercase = min_lowercase
        self.min_uppercase = min_uppercase
        self.min_digits = min_digits
        self.min_special = min_special
        self.min_length = min_length
        self.max_length = max_length
        self.allow_unicode = allow_unicode

    def is_password_accepted(self, password: str) -> bool:
        lowercase = 0
        uppercase = 0
        digits = 0
        special = 0

        if len(password) < self.min_length or len(password) > self.max_length:
            # Password length does not match
            return False
        
        # count the number of chars for each class
        for char in password:
            if not char.isascii():
                # probably a Unicode char
                if self.allow_unicode:
                    special += 1
                else:
                    return False
            elif char.isdigit():
                digits += 1
            elif char.isalpha():
                if char.islower():
                    lowercase += 1
                else:
                    uppercase += 1
            else:
                special += 1

        return (lowercase >= self.min_lowercase
                and uppercase >= self.min_uppercase
                and digits >= self.min_digits
                and special >= self.min_special)


def create_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser("Password Policy Filter",
                                 description="Filter a password list to only return entries that match a given password policy",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    general = ap.add_argument_group(title="General options")
    general.add_argument("-i", "--input-file", nargs="?", help="input file with a single password in each line. When no file is given stdin will be used instead")
    general.add_argument("-o", "--output-file", nargs="?", help="destination file for the output. When no file is given stdout will be used instead")

    pw_policy = ap.add_argument_group(title="Password policy options")
    pw_policy.add_argument("-l", "--lowercase", type=int, help="require a minimum of X lowercase characters", default=0)
    pw_policy.add_argument("-u", "--uppercase", type=int, help="require a minimum of X uppercase characters", default=0)
    pw_policy.add_argument("-d", "--digits", type=int, help="require a minimum of X digits", default=0)
    pw_policy.add_argument("-s", "--special", type=int, help="require a minimum of X special characters", default=0)
    pw_policy.add_argument("-m", "--min-length", type=int, help="require password length >= X characters", default=0)
    pw_policy.add_argument("-M", "--max-length", type=int, help="require password length <= X characters", default=256)
    pw_policy.add_argument("-a", "--ascii-only", action="store_true", help="only allow ASCII characters")
    return ap



def process_lines(input_stream, output_file: Optional, pw_policy: SimplePasswordPolicy) -> None:
    for line in input_stream:
        password = line
        # Remove the trailing \n, \r\n, etc. Calling rstrip() would remove spaces, that may be part of the password
        while password.endswith("\n") or password.endswith("\r"):
            password = password[:-1]

        if pw_policy.is_password_accepted(password):
            if output_file:
                # Do not flush for performance/disk health reasons
                output_file.write(line)
            else:
                print(password)
        # print("Read:", password)    


def main() -> int:
    ap = create_argparser()
    args = ap.parse_args()

    pw_policy = SimplePasswordPolicy(min_lowercase=args.lowercase, min_uppercase=args.uppercase, min_digits=args.digits,
                                     min_special=args.special, min_length=args.min_length, max_length=args.max_length, allow_unicode=not args.ascii_only)

    input_stream = open(args.input_file, "r") if args.input_file else sys.stdin
    output_stream = open(args.output_file) if args.output_file else sys.stdout

    if args.output_file:
        with open(args.output_file, "w") as f:
            process_lines(input_stream, f, pw_policy)
    else:
        process_lines(input_stream, None, pw_policy)

    return 0


if __name__ == '__main__':
    code = main()
    sys.exit(code)

