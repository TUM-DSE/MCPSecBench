import subprocess
import sys
import json
import csv
import pyperclip
from pwn import *


def main(mode: str):
    print("Hello from MCPSecBench!")
    print("This script shows results of example attacks")
    attacks = ["Tool Poisoning Attack", "Tool Shadowing Attack", "Package Name Squatting(Server Name)", "Package Name Squatting(Tool Name)", "Data Exfiltration", "Prompt Injection", "Rug Pull", "Indirect Prompt Injection", "Sandbox Escape", "Tool Misuse via Confused AI", "Vulnerable Server"]
    command = ["python3", "download.py"]

    loop_res = []
    if int(mode) < 2:
        server = process(command)
        i_command = ["python3", "client.py", mode]
        sh = process(i_command)
        sh.recvuntil(b"User Input:")
    else:
        print("TEO: pyGUI no longer available")
        return;

    flag = 0
    file = open('data.json', 'r')
    res = open('experiment.csv', 'w')
    csv_w = csv.writer(res)
    csv_w.writerows([attacks])
    pr = json.load(file)
    for j in range(15):
        if int(mode) < 2:
            for i in range(len(pr)):
                sh.sendline(pr[i]['prompt'])
                msg = sh.recvuntil(b"User Input:")
                print(msg)
                if flag == 0 and pr[i]['attack'] == "Rug Pull":
                    flag = 1
                    sh.sendline(pr[i]['prompt'])
                    msg = sh.recvuntil(b"User Input:")
                sh.sendline(pr[i]['result'])
                msg = sh.recvuntil(b"User Input:")
                if b"Attack success" in msg:
                    loop_res.append("1")
                    print(f"{attacks[i]}: Attack success")
                elif b"Attack detected" in msg:
                    loop_res.append("-1")
                    print(f"{attacks[i]}: Attack detected")
                else:
                    loop_res.append("0")
                    print(f"{attacks[i]}: Attack fail")
            csv_w.writerows([loop_res])
            loop_res = []
            sh.sendline(b"forget all conversation")
            sh.recvuntil(b"User Input:")

    # sh.interactive()


if __name__ == "__main__":
    main(sys.argv[1])
