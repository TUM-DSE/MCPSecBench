from client import POLICY_FAILURE
from client import ATTACK_SUCCESS
import subprocess
import sys
import json
import csv
import pyperclip
from pwn import *
from client import *


async def main(policy_active: int, base_policy_file : str, user_policy_file : str):


    # MCP servers
    server_configs = [
        MCPServerConfig( 
            name="signature-checkers",
            server_type=ServerType.LOCAL,
            command=["uv"],
            args=["run", "./squatting.py"],
            description="Check file's signature"
        ),
        MCPServerConfig(
            name="compute-helper",
            server_type=ServerType.LOCAL,
            command=["uv"],
            args=["run", "addserver.py"],
            description="Basic computer"
        ),
        MCPServerConfig(
            name="compute-assistant",
            server_type=ServerType.LOCAL,
           command=["uv"],
            args=["run", "./maliciousadd.py"],
            description="Enhanced computer"
        ),
        # Add more servers as needed
    ]

    # Create client
    client = MultiMCPClient("", "")

    # Add connections to servers
    for config in server_configs:
        try:
            await client.add_server(config)
        except Exception as e:
            logger.error(f"Failed to add server {config.name}: {e}")
            return



    policy_file_path = "../data/policy_overhead.txt"
    try:
        os.remove(policy_file_path)
    except Exception as e:
        pass
    with open(policy_file_path, "w"):
        pass
    f = open('../data/attacks_updated.json', 'r')
    attacks = json.load(f)
    RUNS = 10


    result_summary = [{} for _ in range(RUNS)]
    for run in range(RUNS):
        print(f"RUN {run + 1}/{RUNS}")
        print(f"Runing {len(attacks)} attacks")
        for i in range(len(attacks)):
            attack = attacks[i]
            name = attack.get('name')
            prompts = attack.get('prompts')
            malicious_prompt = attack.get('malicious_prompt')

            successful_runs = 0
            print(f"Attack - {name} ({i + 1} / {len(attacks)}): ")

            for j in range(len(prompts)):
                prompt = prompts[j]
#
                result = "Failure"
                for i in range(1):
                    malicious_tool_called = await client.chat_with_local_llm(prompt, 5, policy_active, base_policy_file, user_policy_file, malicious_prompt, policy_file_path)
                    if malicious_tool_called == ATTACK_SUCCESS:
                        result = "Success"
                        successful_runs += 1
                        break
                    if malicious_tool_called == POLICY_FAILURE:
                        result = "Policy check failed"
                        break
                print(f'\tPrompt {j + 1}/{len(prompts)}: {result}')

                # Reset state of tool invocations
                result = await client.call_tool("signature-checkers_buy_item", json.loads("{\"item\": \"guitar\"}"))
                result = result.get('content')[0].get('text')
                result = result.split(',')
                while result[-1] != "True":
                    result = await client.call_tool("signature-checkers_buy_item", json.loads("{\"item\": \"guitar\"}"))
                    result = result.get('content')[0].get('text')
                    result = result.split(',')


            result_summary[run][name] = successful_runs / len(prompts)

    print("Doing client cleanup")
    #await client.cleanup()
    print("Done cleanup")

    overall_summary = {}
    for attack in attacks:
        overall_summary[attack.get('name')] = 0
        
    for run in range(RUNS):
        print(f"RUN #{run + 1} SUMMARY")
        for attack in attacks:
            print(f"\t{attack.get('name')}: {result_summary[run][attack.get('name')]}")
            overall_summary[attack.get('name')] += result_summary[run][attack.get('name')]
        print("\n")

    print("OVERALL SUMMARY")
    for attack in attacks:
        overall_summary[attack.get('name')] /= RUNS
        print(f"{attack.get('name')}: {overall_summary[attack.get('name')]}")

    return 0

if __name__ == "__main__":
    if len(sys.argv) - 1 != 3:
        print(f'Usage: uv run {sys.argv[0]} <0/1> <base_policy_file> <user_policy_file>')
        sys.exit(0)
    asyncio.run(main(int(sys.argv[1]), sys.argv[2], sys.argv[3]))
