import re           # built in library for regular expressions (pattern matching)
import json         # to save results in JSON file 
import pathlib      # easier file and folder traversal 
import time         # to measure how long the scan takes 

# ---------------------------------------------------
# 1. Define Vulnerability patterns (expandable later)
# ---------------------------------------------------
# defining patterns that are risky or vulnerable to injections/user input manipulation 
patterns = {
    "eval": re.compile(r"\beval\("), # dynamic code execution (dangerous)
    "exec": re.compile(r"\bexec\("), # same idea - executes arbitrary code 
    "strcpy": re.compile(r"\bstrcpy\("), # unsafe C function , can overflow buffer
    "gets": re.compile(r"\bgets\("), # another unsafe C function 
    "hardcoded_password":re.compile(r'password\s*[:=]\s*["\']\w+["\']', re.IGNORECASE), # finds literal hardcoded passwords 
    "sql_injection":re.compile(r"SELECT.*FROM.*[\"']\s*\+",re.IGNORECASE) # finds SQL queries built with string concatenation (possible SQL injection)
}

# -----------------------------------------------------
# 2. File Extensions to scan
# -----------------------------------------------------

extensions = (".py",".c",".cpp",".js",".ts",".java",".go")

# -----------------------------------------------------
# 3. Folders to Ignore (save time + skip dependencies)
# -----------------------------------------------------

ignore_dirs = {"venv","node_modules","__pycache__", "build", ".git"}

# -----------------------------------------------------
# 4. Main scanning function 
# -----------------------------------------------------

def scan_directory(root_dir="."):
    results = [] # storing results 
    # save start time 
    t0 = time.time()
    # walk recursively through all files in the directory 
    for path in pathlib.Path(root_dir).rglob("*"):
        # skip folders like venv or node_modules 
        if path.is_dir() and path.name in ignore_dirs:
            continue
        # skip if not in desired extensions 
        if not path.suffix.lower() in extensions:
            continue
        # read the file contents safely (ignore encoding errors)
        try: 
            text = path.read_text(errors="ignore")
        except Exception:
            continue # skip unreadable files 
        # for each pattern, look for matches inside the files 
        for name, pattern in patterns.items():
            # for every match found ... 
            for match in pattern.finditer(text):
                # count number of newline characters occure before the match
                # figuring out what line number its on 
                line_num = text.count("\n", 0, match.start())+1
                # extract snippet of code around match 
                snippet = text[match.start():match.start() + 120].replace("\n", " ")
                # append the match with details : name of file, pattern, what line , and snippet 
                results.append({
                    "file": str(path), 
                    "pattern": name, 
                    "line": line_num, 
                    "snippet":snippet
                })
    # calculate total time needed to complete 
    elapsed = time.time() - t0
    # quick summary to terminal 
    print(f"✅ Scan complete: {len(results)} findings in {elapsed:.2f} seconds")
    # save detailed results to JSON file for later use (UI or ML layers)
    with open("scan_regex.json", "w") as f: 
        json.dump(results, f, indent = 2)
    print("📁 Results saved to scan_regex.json")

# -----------------------------------------------------
# 5. Entry point
# -----------------------------------------------------
# this allows the script to be imported as a module later without auto-running 
if __name__ == "__main__":
    scan_directory(".")