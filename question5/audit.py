import subprocess
import json
import csv
import os
import sys

# -------------------------------------------
# Welcome message
# -------------------------------------------

def print_welcome():
    print("==========================================")
    print("     Node.js Dependency Security Audit   ")
    print("==========================================")
    print()
    print("This script scans your package.json for")
    print("vulnerable dependencies and generates")
    print("a CSV report.")
    print()
    print("Before running make sure you have:")
    print("  1. Node.js installed  -> https://nodejs.org")
    print("  2. npm installed      -> comes with Node.js")
    print("  3. package.json in the current folder")
    print()
    print("Then run:")
    print("  npm install      (installs dependencies first)")
    print("  python3 audit.py (runs this script)")
    print()
    input("Press Enter to start or Ctrl+C to exit...")
    print()

# -------------------------------------------
# Check requirements
# -------------------------------------------

def check_requirements():
    print("Checking requirements...")

    # check npm is installed
    result = subprocess.run(["npm", "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        print("npm not found. Install Node.js from https://nodejs.org")
        return False
    print("  npm version: " + result.stdout.strip())

    # check package.json exists
    if not os.path.exists("package.json"):
        print("package.json not found in current folder")
        return False
    print("  package.json found")

    # check node_modules exists
    if not os.path.exists("node_modules"):
        print("node_modules not found. Run: npm install")
        return False
    print("  node_modules found")

    print("All requirements met")
    print()
    return True

# -------------------------------------------
# Get installed version of a package
# -------------------------------------------

def get_installed_version(package_name):
    # build the path to the package's package.json
    path = os.path.join("node_modules", package_name, "package.json")

    # try to open and read it
    try:
        f    = open(path)
        data = json.load(f)
        f.close()

        # get the version field
        version = data.get("version", "unknown")
        return version

    except Exception:
        return "unknown"

# -------------------------------------------
# Run npm audit and get results
# -------------------------------------------

def run_audit():
    print("Running npm audit...")

    result = subprocess.run(
        ["npm", "audit", "--json"],
        capture_output=True,
        text=True
    )

    if not result.stdout:
        print("No output from npm audit")
        return None

    try:
        data = json.loads(result.stdout)
        return data
    except Exception:
        print("Failed to parse npm audit output")
        return None

# -------------------------------------------
# Parse vulnerabilities into simple list
# -------------------------------------------

def parse_vulnerabilities(audit_data):
    print("Parsing vulnerabilities...")

    vulnerabilities = audit_data.get("vulnerabilities", {})
    results = []

    for package_name, details in vulnerabilities.items():

        # get basic info
        severity  = details.get("severity", "unknown")
        is_direct = details.get("isDirect", False)
        fix       = details.get("fixAvailable", False)
        via       = details.get("via", [])

        # get the installed version
        installed_version = get_installed_version(package_name)

        # get the vulnerability title
        title = "See npm advisory"
        for v in via:
            if isinstance(v, dict):
                if v.get("title"):
                    title = v.get("title")
                    break

        # build the description
        # format: "Command Injection in lodash in version 4.17.10"
        description = title + " in version " + installed_version

        # build the remediation and fix command
        # format: "Upgrade lodash to 4.18.1"
        if isinstance(fix, dict):
            fix_name    = fix["name"]
            fix_version = fix["version"]
            remediation = "Upgrade " + fix_name + " to " + fix_version
            fix_command = "npm install " + fix_name + "@" + fix_version

        elif fix is True:
            remediation = "Run npm audit fix"
            fix_command = "npm audit fix"

        else:
            remediation = "No fix available"
            fix_command = "No fix available"

        # build direct dependency label
        if is_direct:
            direct = "Yes"
        else:
            direct = "No"

        # add to results list
        results.append({
            "package":           package_name,
            "installed_version": installed_version,
            "severity":          severity,
            "direct":            direct,
            "description":       description,
            "remediation":       remediation,
            "fix_command":       fix_command
        })

    # sort by severity so critical comes first
    severity_order = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "unknown": 4}
    results.sort(key=lambda x: severity_order.get(x["severity"], 99))

    return results

# -------------------------------------------
# Print summary to screen
# -------------------------------------------

def print_summary(audit_data, vulnerabilities):
    meta = audit_data.get("metadata", {}).get("vulnerabilities", {})

    print()
    print("==========================================")
    print("              Summary                    ")
    print("==========================================")
    print("  Critical : " + str(meta.get("critical", 0)))
    print("  High     : " + str(meta.get("high", 0)))
    print("  Moderate : " + str(meta.get("moderate", 0)))
    print("  Low      : " + str(meta.get("low", 0)))
    print("  Total    : " + str(meta.get("total", 0)))
    print()

    print("==========================================")
    print("       Vulnerabilities Found             ")
    print("==========================================")

    for v in vulnerabilities:
        if v["severity"] == "critical" or v["severity"] == "high":
            print("  [" + v["severity"].upper() + "] " + v["package"] + " v" + v["installed_version"])
            print("    Description : " + v["description"])
            print("    Remediation : " + v["remediation"])
            print("    Fix command : " + v["fix_command"])
            print()

# -------------------------------------------
# Count how many issues can be fixed
# -------------------------------------------

def count_fixable(vulnerabilities):
    fixable     = 0
    not_fixable = 0

    for v in vulnerabilities:
        if v["fix_command"] == "No fix available":
            not_fixable = not_fixable + 1
        else:
            fixable = fixable + 1

    print("==========================================")
    print("          Fixable Issues                 ")
    print("==========================================")
    print("  Can be fixed     : " + str(fixable))
    print("  No fix available : " + str(not_fixable))
    print("  Total            : " + str(len(vulnerabilities)))
    print()

# -------------------------------------------
# Generate CSV report
# -------------------------------------------

def generate_csv(vulnerabilities, filename="report.csv"):
    print("Saving report to " + filename + "...")

    fields = [
        "package",
        "installed_version",
        "severity",
        "direct",
        "description",
        "remediation",
        "fix_command"
    ]

    f      = open(filename, "w", newline="")
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(vulnerabilities)
    f.close()

    print("Report saved to " + filename)
    print()

    # also print to screen
    print("package,installed_version,severity,description,remediation")
    for v in vulnerabilities:
        line = v["package"] + "," + v["installed_version"] + "," + v["severity"] + "," + v["description"] + "," + v["remediation"]
        print(line)

# -------------------------------------------
# Main - calls everything in order
# -------------------------------------------

def main():

    # step 1 - show welcome
    print_welcome()

    # step 2 - check npm and package.json exist
    if not check_requirements():
        sys.exit(1)

    # step 3 - run npm audit and get raw results
    audit_data = run_audit()
    if not audit_data:
        sys.exit(1)

    # step 4 - parse raw results into simple list
    vulnerabilities = parse_vulnerabilities(audit_data)

    # step 5 - print summary to screen
    print_summary(audit_data, vulnerabilities)

    # step 6 - count how many can be fixed
    count_fixable(vulnerabilities)

    # step 7 - save to CSV file
    generate_csv(vulnerabilities)

if __name__ == "__main__":
    main()
