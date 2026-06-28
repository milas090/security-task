import csv
import os
from dataclasses import dataclass
from abc import ABC, abstractmethod

import boto3
from botocore.exceptions import ClientError
from google.cloud import storage
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient


# common data structure returned by every fetcher
@dataclass
class BucketInfo:
    cloud: str
    bucket_name: str
    public_access: str       # "Yes" or "No"
    encryption_enabled: str  # "Yes" or "No"


# base class — each cloud implements the abstract methods below
# fetch() is defined once here and calls them
class Fetcher(ABC):

    cloud_name: str

    @abstractmethod
    def fetch_buckets(self) -> list:
        pass

    @abstractmethod
    def get_bucket_name(self, bucket) -> str:
        pass

    @abstractmethod
    def check_public_access(self, bucket) -> str:
        pass

    @abstractmethod
    def check_encryption(self, bucket) -> str:
        pass

    def fetch(self) -> list[BucketInfo]:
        results = []
        for bucket in self.fetch_buckets():
            results.append(BucketInfo(
                cloud=self.cloud_name,
                bucket_name=self.get_bucket_name(bucket),
                public_access=self.check_public_access(bucket),
                encryption_enabled=self.check_encryption(bucket)
            ))
        return results


# AWS — uses Boto3
# reads credentials from ~/.aws/credentials or env vars
class AWSFetcher(Fetcher):

    cloud_name = "AWS"

    def __init__(self):
        self.client = boto3.client("s3")

    def fetch_buckets(self) -> list:
        response = self.client.list_buckets()
        return response["Buckets"]

    def get_bucket_name(self, bucket) -> str:
        return bucket["Name"]

    def check_public_access(self, bucket) -> str:
        name = self.get_bucket_name(bucket)
        try:
            resp = self.client.get_public_access_block(Bucket=name)
            config = resp["PublicAccessBlockConfiguration"]
            is_private = (
                config.get("BlockPublicAcls", False) and
                config.get("IgnorePublicAcls", False) and
                config.get("BlockPublicPolicy", False) and
                config.get("RestrictPublicBuckets", False)
            )
            return "No" if is_private else "Yes"
        except ClientError:
            # no block config means public access is not restricted
            return "Yes"

    def check_encryption(self, bucket) -> str:
        name = self.get_bucket_name(bucket)
        try:
            self.client.get_bucket_encryption(Bucket=name)
            return "Yes"
        except ClientError:
            return "No"


# GCP — uses Google Cloud Storage SDK
# needs: gcloud auth application-default login
class GCPFetcher(Fetcher):

    cloud_name = "GCP"

    def __init__(self):
        self.client = storage.Client()
        self.project = os.environ.get("GCP_PROJECT_ID")

    def fetch_buckets(self) -> list:
        return list(self.client.list_buckets(project=self.project))

    def get_bucket_name(self, bucket) -> str:
        return bucket.name

    def check_public_access(self, bucket) -> str:
        try:
            policy = bucket.get_iam_policy()
            for binding in policy.bindings:
                if "allUsers" in binding["members"] or \
                   "allAuthenticatedUsers" in binding["members"]:
                    return "Yes"
            return "No"
        except Exception:
            return "No"

    def check_encryption(self, bucket) -> str:
        # GCP always encrypts — either Google managed or customer managed key
        return "Yes"


# Azure — uses Azure SDK
# needs: az login or AZURE_SUBSCRIPTION_ID + credentials in env
class AzureFetcher(Fetcher):

    cloud_name = "Azure"

    def __init__(self):
        self.subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        credential = DefaultAzureCredential()
        self.storage_client = StorageManagementClient(credential, self.subscription_id)

    def fetch_buckets(self) -> list:
        # no single "list all containers" API in Azure
        # have to go: storage accounts -> containers inside each account
        containers = []
        accounts = self.storage_client.storage_accounts.list()
        for account in accounts:
            resource_group = account.id.split("/")[4]
            account_containers = self.storage_client.blob_containers.list(
                resource_group, account.name
            )
            for container in account_containers:
                # attach account so check_encryption can reach account-level settings
                container._account = account
                containers.append(container)
        return containers

    def get_bucket_name(self, bucket) -> str:
        return bucket.name

    def check_public_access(self, bucket) -> str:
        if bucket.public_access is None or bucket.public_access == "None":
            return "No"
        return "Yes"

    def check_encryption(self, bucket) -> str:
        account = bucket._account
        try:
            blob_encryption = account.encryption.services.blob
            if blob_encryption and blob_encryption.enabled:
                return "Yes"
            return "No"
        except Exception:
            return "No"


def write_csv(buckets: list[BucketInfo], filename: str = "report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["cloud", "bucket_name", "public_access", "encryption_enabled"])
        writer.writeheader()
        for bucket in buckets:
            writer.writerow({
                "cloud": bucket.cloud,
                "bucket_name": bucket.bucket_name,
                "public_access": bucket.public_access,
                "encryption_enabled": bucket.encryption_enabled
            })
    print(f"Report written to {filename}")


def main():
    print("==========================================")
    print("       Cloud Storage Security Scanner    ")
    print("==========================================")
    print()
    print("Make sure you are authenticated:")
    print("  AWS   -> aws configure")
    print("  GCP   -> gcloud auth application-default login")
    print("  Azure -> az login")
    print()
    input("Press Enter to start...")

    fetcher_classes = [AWSFetcher, GCPFetcher, AzureFetcher]

    all_buckets = []
    for fetcher_class in fetcher_classes:
        try:
            fetcher = fetcher_class()
            buckets = fetcher.fetch()
            all_buckets.extend(buckets)
        except Exception as e:
            print(f"warning ({fetcher_class.cloud_name}): {e}")
            continue

    write_csv(all_buckets)


if __name__ == "__main__":
    main()
