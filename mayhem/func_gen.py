#!/usr/bin/python3


val = 0
with open("./mayhem/funcs.txt", "r") as infile:
    for line in infile:
        func = line.strip()
        code = f"""
elif rand == {val}:
    {func}"""
        val += 1
        print(code, end="")