import subprocess
import json
import csv
import os

# -------------------------------------------
# Welcome message and instructions
# this is the FIRST function in the file
# it runs before anything else
# -------------------------------------------

def print_welcome():
    print("==========================================")
    print("      Cloud Storage Security Scanner     ")
    print("==========================================")
    print()
    print("This script scans AWS, GCP and Azure")
    print("storage buckets for public access and")
    print("encryption settings.")
    print()
    print("==========================================")
    print("         BEFORE YOU RUN THIS SCRIPT      ")
    print("==========================================")
    print()
    print("STEP 1 - Install the cloud CLIs")
    print()
    print("  AWS CLI:")
    print('  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip')
    print("  unzip /tmp/awscliv2.zip -d /tmp")
    print("  sudo /tmp/aws/install")
    print()
    print("  GCP CLI:")
    print("  curl https://sdk.cloud.google.com | bash")
    print("  exec -l $SHELL")
    print()
    print("  Azure CLI:")
    print("  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash")
    print()
    print("------------------------------------------")
    print()
    print("STEP 2 - Set your credentials")
    print()
    print("  AWS:")
    print("  export AWS_ACCESS_KEY_ID=your-key")
    print("  export AWS_SECRET_ACCESS_KEY=your-secret")
    print("  export AWS_REGION=us-east-1")
    print()
    print("  GCP:")
    print("  export GCP_PROJECT_ID=your-project-id")
    print("  then run: gcloud auth login")
    print()
    print("  Azure:")
    print("  export AZURE_TENANT_ID=your-tenant-id")
    print("  export AZURE_CLIENT_ID=your-client-id")
    print("  export AZURE_CLIENT_SECRET=your-secret")
    print("  export AZURE_SUBSCRIPTION_ID=your-subscription-id")
    print()
    print("------------------------------------------")
    print()
    print("STEP 3 - Verify each CLI works")
    print()
    print("  AWS:   aws sts get-caller-identity")
    print("  GCP:   gcloud auth list")
    print("  Azure: az account show")
    print()
    print("==========================================")
    print()
    input("Press Enter to start the scan or Ctrl+C to exit...")
    print()

# -------------------------------------------
# Helper: run a CLI command and get output
# takes a list of strings as input
# returns the output text and exit code
# -------------------------------------------

def run(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout, result.returncode
    except Exception as e:
        return "", 1

# -------------------------------------------
# AWS: authenticate and scan
# -------------------------------------------

def authenticate_aws():
    print("[AWS] Checking credentials...")

    if not os.getenv("AWS_ACCESS_KEY_ID"):
        print("[AWS] Missing AWS_ACCESS_KEY_ID")
        print("[AWS] Run: export AWS_ACCESS_KEY_ID=your-key")
        return False

    if not os.getenv("AWS_SECRET_ACCESS_KEY"):
        print("[AWS] Missing AWS_SECRET_ACCESS_KEY")
        print("[AWS] Run: export AWS_SECRET_ACCESS_KEY=your-secret")
        return False

    if not os.getenv("AWS_REGION"):
        print("[AWS] AWS_REGION not set, using us-east-1")
        os.environ["AWS_REGION"] = "us-east-1"

    _, code = run(["aws", "sts", "get-caller-identity"])
    if code != 0:
        print("[AWS] Credentials are invalid or expired")
        print("[AWS] Run: aws configure")
        return False

    print("[AWS] Authenticated successfully")
    return True

def scan_aws():
    print("[AWS] Scanning S3 buckets...")
    results = []

    out, code = run(["aws", "s3api", "list-buckets", "--output", "json"])
    if code != 0:
        print("[AWS] Failed to list buckets")
        return results

    data = json.loads(out)
    buckets = data.get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]

        # check public access
        public = "No"
        out, code = run(["aws", "s3api", "get-public-access-block", "--bucket", name, "--output", "json"])
        if code == 0:
            block = json.loads(out).get("PublicAccessBlockConfiguration", {})
            all_blocked = (
                block.get("BlockPublicAcls", False) and
                block.get("BlockPublicPolicy", False) and
                block.get("IgnorePublicAcls", False) and
                block.get("RestrictPublicBuckets", False)
            )
            public = "No" if all_blocked else "Yes"
        else:
            public = "Yes"

        # check encryption
        encryption = "No"
        out, code = run(["aws", "s3api", "get-bucket-encryption", "--bucket", name, "--output", "json"])
        if code == 0:
            encryption = "Yes"

        results.append({
            "cloud": "AWS",
            "bucket_name": name,
            "public_access": public,
            "encryption_enabled": encryption
        })

        print(f"  {name} -> public: {public}, encryption: {encryption}")

    return results

# -------------------------------------------
# GCP: authenticate and scan
# -------------------------------------------

def authenticate_gcp():
    print("[GCP] Checking credentials...")

    project_id = os.getenv("GCP_PROJECT_ID")
    if not project_id:
        print("[GCP] Missing GCP_PROJECT_ID")
        print("[GCP] Run: export GCP_PROJECT_ID=your-project-id")
        return False

    _, code = run(["gcloud", "config", "set", "project", project_id])
    if code != 0:
        print("[GCP] Failed to set project")
        return False

    _, code = run(["gcloud", "auth", "list"])
    if code != 0:
        print("[GCP] Not authenticated")
        print("[GCP] Run: gcloud auth login")
        return False

    print("[GCP] Authenticated successfully")
    return True

def scan_gcp():
    print("[GCP] Scanning GCS buckets...")
    results = []

    out, code = run(["gsutil", "ls"])
    if code != 0:
        print("[GCP] Failed to list buckets")
        return results

    buckets = [
        line.strip().replace("gs://", "").rstrip("/")
        for line in out.strip().split("\n")
        if line.strip()
    ]

    for name in buckets:

        # check public access
        public = "No"
        out, code = run(["gsutil", "iam", "get", f"gs://{name}"])
        if code == 0:
            if "allUsers" in out or "allAuthenticatedUsers" in out:
                public = "Yes"

        # check encryption
        encryption = "No"
        out, code = run(["gsutil", "encryption", "-l", f"gs://{name}"])
        if code == 0 and "No encryption key" not in out:
            encryption = "Yes"

        results.append({
            "cloud": "GCP",
            "bucket_name": name,
            "public_access": public,
            "encryption_enabled": encryption
        })

        print(f"  {name} -> public: {public}, encryption: {encryption}")

    return results

# -------------------------------------------
# Azure: authenticate and scan
# -------------------------------------------

def authenticate_azure():
    print("[Azure] Checking credentials...")

    tenant_id       = os.getenv("AZURE_TENANT_ID")
    client_id       = os.getenv("AZURE_CLIENT_ID")
    client_secret   = os.getenv("AZURE_CLIENT_SECRET")
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

    if not tenant_id:
        print("[Azure] Missing AZURE_TENANT_ID")
        print("[Azure] Run: export AZURE_TENANT_ID=your-tenant-id")
        return False
    if not client_id:
        print("[Azure] Missing AZURE_CLIENT_ID")
        print("[Azure] Run: export AZURE_CLIENT_ID=your-client-id")
        return False
    if not client_secret:
        print("[Azure] Missing AZURE_CLIENT_SECRET")
        print("[Azure] Run: export AZURE_CLIENT_SECRET=your-secret")
        return False
    if not subscription_id:
        print("[Azure] Missing AZURE_SUBSCRIPTION_ID")
        print("[Azure] Run: export AZURE_SUBSCRIPTION_ID=your-subscription-id")
        return False

    _, code = run([
        "az", "login",
        "--service-principal",
        "--tenant", tenant_id,
        "--username", client_id,
        "--password", client_secret
    ])
    if code != 0:
        print("[Azure] Login failed. Check your credentials.")
        return False

    _, code = run(["az", "account", "set", "--subscription", subscription_id])
    if code != 0:
        print("[Azure] Failed to set subscription")
        return False

    print("[Azure] Authenticated successfully")
    return True

def scan_azure():
    print("[Azure] Scanning Blob Storage containers...")
    results = []

    out, code = run(["az", "storage", "account", "list", "--output", "json"])
    if code != 0:
        print("[Azure] Failed to list storage accounts")
        return results

    accounts = json.loads(out)

    for account in accounts:
        account_name = account["name"]

        out, code = run([
            "az", "storage", "container", "list",
            "--account-name", account_name,
            "--output", "json",
            "--auth-mode", "login"
        ])
        if code != 0:
            continue

        containers = json.loads(out)

        for container in containers:
            name  = container["name"]
            props = container.get("properties", {})

            # check public access
            public_access = props.get("publicAccess", "None")
            public = "Yes" if public_access and public_access != "None" else "No"

            # check encryption
            encryption_settings = account.get("encryption", {})
            services            = encryption_settings.get("services", {})
            blob_encrypted      = services.get("blob", {}).get("enabled", False)
            encryption          = "Yes" if blob_encrypted else "No"

            results.append({
                "cloud": "Azure",
                "bucket_name": f"{account_name}/{name}",
                "public_access": public,
                "encryption_enabled": encryption
            })

            print(f"  {account_name}/{name} -> public: {public}, encryption: {encryption}")

    return results

# -------------------------------------------
# Generate CSV report
# -------------------------------------------

def generate_csv(results, filename="report.csv"):
    print()
    print(f"Saving results to {filename}...")

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["cloud", "bucket_name", "public_access", "encryption_enabled"])
        writer.writeheader()
        writer.writerows(results)

    print(f"Done. Report saved to {filename}")
    print()
    print("==========================================")
    print("                Results                  ")
    print("==========================================")
    print("cloud,bucket_name,public_access,encryption_enabled")
    for row in results:
        print(f"{row['cloud']},{row['bucket_name']},{row['public_access']},{row['encryption_enabled']}")

# -------------------------------------------
# Main
# this is what runs when you type:
# python3 scanner.py
# it calls every function in order
# -------------------------------------------

def main():
    # 1. show welcome and instructions
    print_welcome()

    all_results = []

    # 2. authenticate and scan each cloud
    print("--- AWS ---")
    if authenticate_aws():
        all_results += scan_aws()
    else:
        print("[AWS] Skipping scan, authentication failed")
    print()

    print("--- GCP ---")
    if authenticate_gcp():
        all_results += scan_gcp()
    else:
        print("[GCP] Skipping scan, authentication failed")
    print()

    print("--- Azure ---")
    if authenticate_azure():
        all_results += scan_azure()
    else:
        print("[Azure] Skipping scan, authentication failed")
    print()

    # 3. generate the CSV report
    generate_csv(all_results)

# this means: only run main() if we run this file directly
# python3 scanner.py  →  runs main()
# import scanner      →  does not run main()
if __name__ == "__main__":
    main()
