import subprocess
from pathlib import Path
import re


def test_input(binary_path, input_path,args):
    with open(input_path, "rb") as f:
        data = f.read()

    try:
        result = subprocess.run(
            [binary_path ]+[args], 
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        return result.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return None 


base64_dir="/home/edoardo/materiale_tesi/Tesi/testbench/LAVA-M-testbench/base64/base64"
base64_crash_dirs=[
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/afl1/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/afl2/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/afl3/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/mine1/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/mine2/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/mine3/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/zafl1/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/zafl2/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/base64/zafl3/default/crashes"
]
tests=["afl1","afl2","afl3","mine1","mine2","min3","zafl1","zafl2","zafl3"]

uniq_dir="/home/edoardo/materiale_tesi/Tesi/testbench/LAVA-M-testbench/uniq/uniq"
uniq_crash_dirs=[
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/afl1/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/afl2/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/afl3/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/mine1/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/mine2/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/mine3/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/zafl1/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/zafl2/default/crashes",
    "/home/edoardo/materiale_tesi/Tesi/tests/experiment2/uniq/zafl3/default/crashes"
]

bug_id_re=re.compile(r"triggered bug (\d+)")

print("Base64 uniq crashes")
for i,crash_dir in enumerate(base64_crash_dirs):
    print("    running "+tests[i])
    c_dir=Path(crash_dir)
    if not c_dir.is_dir():
        print("Crash dir not found")
        exit(-1)
    inputs = sorted(
        p for p in c_dir.iterdir()
        if p.is_file() and p.name != "README.txt"
    )

    print(f"        found {len(inputs)}")

    results = []
    for i, input_path in enumerate(inputs, 1):
        output = test_input(base64_dir, input_path,"-d")
        bug_ids = sorted(set(bug_id_re.findall(output)))
        for bug_id in bug_ids:
            if bug_id not in results:
                results.append(bug_id)
    print(sorted(results))
    print(len(results))
print("_____________________________________________________________")
print("uniq uniq crashes")
for i,crash_dir in enumerate(uniq_crash_dirs):
    print("    running "+tests[i])
    c_dir=Path(crash_dir)
    if not c_dir.is_dir():
        print("Crash dir not found")
        exit(-1)
    inputs = sorted(
        p for p in c_dir.iterdir()
        if p.is_file() and p.name != "README.txt"
    )

    print(f"        found {len(inputs)}")

    results = []
    for i, input_path in enumerate(inputs, 1):
        output = test_input(uniq_dir, input_path,"")
        bug_ids = sorted(set(bug_id_re.findall(output)))
        for bug_id in bug_ids:
            if bug_id not in results:
                results.append(bug_id)
    print(sorted(results))
    print(len(results))

