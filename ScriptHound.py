#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ScriptHound 🐕 — Sniffing out Nmap scripts (and any files) fast.
Author: Harsh Katiyar
"""

import os
import platform
import sys
import time
from tabulate import tabulate

# ============ Color codes ============
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ENDC = '\033[0m'

# ============ Preferences (edit these to your liking) ============
PREF = {
    "name": "ScriptHound",
    "emoji": "🐕",
    "tagline": "Sniffing out Nmap scripts fast.",
    "author": "Harsh Katiyar",
    "accent_primary": Colors.OKGREEN,
    "accent_secondary": Colors.OKBLUE,
    "banner_style": "raptor",   # options: "raptor", "block", "dog"
    "slow_banner": False,       # True = typewriter effect
    "slow_delay": 0.0015        # seconds per character when slow_banner=True
}

# ============ Fancy Banner ============
def _banner_art(style: str) -> str:
    if style == "dog":
        return r"""
        {p}     __
       /{s}^\{p}  (  )   {s}ScriptHound{p}
      / {s}• •{p}\  )    {s}Sniffing scripts since 2025
     (   {s}◡{p}   )/
      \__{s}w w{p}_/       {s}"""[1:]
    if style == "block":
        return r"""

  █████████    █████████  ███████████  ████████████████  ███████████      █████   █████   ███████   █████  ███████████   ███████████████  
 ███░░░░░███  ███░░░░░███░░███░░░░░███░░███░░███░░░░░███░█░░░███░░░█     ░░███   ░░███  ███░░░░░███░░███  ░░███░░██████ ░░███░░███░░░░███ 
░███    ░░░  ███     ░░░  ░███    ░███ ░███ ░███    ░███░   ░███  ░       ░███    ░███ ███     ░░███░███   ░███ ░███░███ ░███ ░███   ░░███
░░█████████ ░███          ░██████████  ░███ ░██████████     ░███          ░███████████░███      ░███░███   ░███ ░███░░███░███ ░███    ░███
 ░░░░░░░░███░███          ░███░░░░░███ ░███ ░███░░░░░░      ░███          ░███░░░░░███░███      ░███░███   ░███ ░███ ░░██████ ░███    ░███
 ███    ░███░░███     ███ ░███    ░███ ░███ ░███            ░███          ░███    ░███░░███     ███ ░███   ░███ ░███  ░░█████ ░███    ███ 
░░█████████  ░░█████████  █████   ███████████████           █████         █████   █████░░░███████░  ░░████████  █████  ░░███████████████  
 ░░░░░░░░░    ░░░░░░░░░  ░░░░░   ░░░░░░░░░░░░░░░           ░░░░░         ░░░░░   ░░░░░   ░░░░░░░     ░░░░░░░░  ░░░░░    ░░░░░░░░░░░░░░░   
                                                                                                                                          
                                                                                                                                          
                                                                                                                                          

        """.rstrip("\n")
    # default "raptor" — fun, pointy, memorable
    return r"""
      {p}        __
     _/o\-._   /  \   {s}S C R I P T H O U N D{p}
  .-'      _\_/    \  {s}Sniffing out Nmap scripts fast{p}
 /  .-.-.  {s}🐾{p}  .-.  \ 
|  /  _  \     / _\  |
\  \ (_) /  _  \(_)/ /
 '-.\___/.-' '-.\__.'
    """.rstrip("\n")

def type_out(text: str, delay: float = 0.002):
    for ch in text:
        print(ch, end='', flush=True)
        time.sleep(delay)
    print()

def print_banner():
    p = PREF["accent_primary"]
    s = PREF["accent_secondary"]
    emoji = PREF["emoji"]
    title = f"{PREF['name']} {emoji}"
    tagline = PREF["tagline"]
    author = PREF["author"]

    art = _banner_art(PREF["banner_style"])
    # inject accent placeholders
    art_colored = art.format(p=p, s=s)

    header = f"{Colors.BOLD}{p}{title}{Colors.ENDC}  {Colors.DIM}{s}{tagline}{Colors.ENDC}"
    author_line = f"{Colors.DIM}by {author}{Colors.ENDC}"
    block = f"{art_colored}\n\n{header}\n{author_line}\n"

    if PREF["slow_banner"]:
        type_out(block, PREF["slow_delay"])
    else:
        print(block)

# ============ Core functionality ============

def detect_os():
    current_os = platform.system().lower()
    print(f"{Colors.DIM}Running on {current_os.capitalize()}{Colors.ENDC}")
    return current_os

def search_file_in_directory(directory, file_name):
    file_name = file_name.lower()
    found_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file_name in file.lower():
                found_files.append(os.path.join(root, file))
    return found_files

def prompt_for_file_name():
    print(f"{PREF['accent_secondary']}Enter the file name to search (e.g., 'ftp', 'ssl', 'example.txt'){Colors.ENDC}")
    return input("File name: ").strip()

def display_results(results, show_full_path):
    if results:
        if show_full_path:
            headers = ["Index", "File Path"]
            table_data = [(i + 1, result) for i, result in enumerate(results)]
        else:
            headers = ["Index", "File Name"]
            table_data = [(i + 1, os.path.basename(result)) for i, result in enumerate(results)]
        print("\nSearch Results:")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"{Colors.DIM}Total matches: {len(results)}{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}No matches found.{Colors.ENDC}")

def pick_search_path(current_os):
    default_search_path = None
    if current_os == 'linux':
        default_search_path = os.path.expanduser('/usr/share/nmap')
        print(f"Default search path set to: {default_search_path}")

    if default_search_path and os.path.isdir(default_search_path):
        use_default = input(f"Use default Nmap scripts folder ({default_search_path})? (y/n): ").lower()
        if use_default == 'y':
            return default_search_path

    while True:
        file_path = input("Enter the full path of the directory to search in: ").strip()
        if os.path.isdir(file_path):
            return file_path
        else:
            print(f"{Colors.FAIL}Invalid directory. Please try again.{Colors.ENDC}")

def main():
    print_banner()
    current_os = detect_os()
    file_path = pick_search_path(current_os)

    while True:
        file_name = prompt_for_file_name()
        print(f"\n{PREF['accent_primary']}Searching for '{file_name}' in '{file_path}'...{Colors.ENDC}\n")
        results = search_file_in_directory(file_path, file_name)

        display_choice = input("Display results as (1) Full Paths or (2) File Names only? [1/2]: ").strip()
        show_full_path = display_choice == '1'

        display_results(results, show_full_path)

        continue_search = input("Search again? (y/n): ").lower()
        if continue_search != 'y':
            print(f"{Colors.OKGREEN}Exiting {PREF['name']}. Goodbye!{Colors.ENDC}")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Interrupted by user.{Colors.ENDC}")
        sys.exit(1)
