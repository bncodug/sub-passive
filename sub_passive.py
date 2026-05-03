import subprocess
import concurrent.futures
import argparse
import os
from datetime import datetime
import re
from typing import List, Callable, Dict, Set
import shutil


def is_tool_installed(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


# ==========================
# Core Execution Layer
# ==========================


def run_command(command: List[str], timeout: int = 60) -> List[str]:
    """Run a command safely and return output lines."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=True
        )
        return result.stdout.strip().splitlines()
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout: {' '.join(command)}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {' '.join(command)}\n{e}")
    return []


# ==========================
# Tool Implementations
# ==========================


def subfinder(domain: str) -> List[str]:
    return run_command(["subfinder", "-d", domain, "-all", "-silent"])


def assetfinder(domain: str) -> List[str]:
    return run_command(["assetfinder", "--subs-only", domain])


def waymore(domain: str) -> List[str]:
    raw = run_command(["waymore", "-i", domain, "-mode", "U"])
    domains: Set[str] = set()

    for line in raw:
        match = re.match(r"https?://([^/]+)", line)
        if match:
            domains.add(match.group(1))

    return list(domains)


TOOLS: Dict[str, Callable[[str], List[str]]] = {
    "subfinder": subfinder,
    "assetfinder": assetfinder,
    "waymore": waymore,
}


# ==========================
# Orchestration Layer
# ==========================


def run_tools(domain: str, selected_tools: List[str]) -> Set[str]:
    results: Set[str] = set()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_map = {}

        for tool in selected_tools:
            if tool not in TOOLS:
                print(f"[!] Unknown tool: {tool}")
                continue

            if not is_tool_installed(tool):
                print(f"[!] Skipping {tool}: not installed")
                continue

            future = executor.submit(TOOLS[tool], domain)
            future_map[future] = tool

        for future in concurrent.futures.as_completed(future_map):
            tool = future_map[future]
            try:
                output = future.result()
                print(f"[✓] {tool}: {len(output)} results")
                results.update(output)
            except Exception as e:
                print(f"[✗] {tool} failed: {e}")

    return results


def save_results(domain: str, results: Set[str], output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)

    filename = f"{domain}-subdomains-{datetime.now():%Y-%m-%d}.txt"
    path = os.path.join(output_dir, filename)

    with open(path, "w") as f:
        for sub in sorted(results):
            f.write(sub + "\n")

    return path


def passive_scan(domain: str, tools: List[str], output_dir: str) -> None:
    print(f"[+] Scanning: {domain}")

    results = run_tools(domain, tools)
    print(f"[+] Unique subdomains: {len(results)}")

    output_path = save_results(domain, results, output_dir)
    print(f"[+] Saved to: {output_path}")


# ==========================
# CLI
# ==========================


def parse_args():
    parser = argparse.ArgumentParser(description="Passive Subdomain Scanner")

    parser.add_argument("domain", help="Target domain (e.g. example.com)")

    parser.add_argument("-o", "--output-dir", default=".", help="Output directory")

    parser.add_argument(
        "-t",
        "--tools",
        nargs="+",
        choices=TOOLS.keys(),
        default=list(TOOLS.keys()),
        help="Tools to use"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    passive_scan(args.domain, args.tools, args.output_dir)


if __name__ == "__main__":
    main()
