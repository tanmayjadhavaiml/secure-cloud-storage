"""
storage.py - AWS S3 storage operations for Secure Cloud Storage.

Responsibilities:
- Initialize Boto3 S3 client using credentials from Streamlit secrets.
- Upload encrypted chunk blocks to S3 under files/<file_id>/block_XXXX.bin.
- Upload file reconstruction metadata to files/<file_id>/metadata.json.
- List stored files by discovering and loading metadata objects.
- Download encrypted chunk blocks from S3.
- Download metadata objects from S3.
"""

import json
import boto3
from botocore.exceptions import ClientError, BotoCoreError


def get_s3_client(aws_access_key_id: str, aws_secret_access_key: str, region_name: str = "eu-north-1"):
    """
    Initializes and returns a Boto3 S3 client with the provided credentials and region.
    """
    return boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name,
    )


def upload_chunk(s3_client, bucket_name: str, file_id: str, block_index: int, data: bytes) -> str:
    """
    Uploads an encrypted file chunk block to AWS S3.
    Object key format: files/<file_id>/block_<index:04d>.bin
    Returns the uploaded S3 key.
    """
    s3_key = f"files/{file_id}/block_{block_index:04d}.bin"
    s3_client.put_object(
        Bucket=bucket_name,
        Key=s3_key,
        Body=data,
        ContentType="application/octet-stream",
    )
    return s3_key


def upload_metadata(s3_client, bucket_name: str, file_id: str, metadata: dict) -> str:
    """
    Uploads file reconstruction metadata as JSON to AWS S3.
    Object key format: files/<file_id>/metadata.json
    Returns the uploaded S3 key.
    """
    s3_key = f"files/{file_id}/metadata.json"
    body = json.dumps(metadata, indent=2).encode("utf-8")
    s3_client.put_object(
        Bucket=bucket_name,
        Key=s3_key,
        Body=body,
        ContentType="application/json",
    )
    return s3_key


def download_chunk(s3_client, bucket_name: str, s3_key: str) -> bytes:
    """
    Downloads an encrypted chunk from AWS S3 using its S3 key.
    Returns chunk bytes.
    """
    response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
    return response["Body"].read()


def download_metadata(s3_client, bucket_name: str, file_id: str) -> dict:
    """
    Downloads and parses the metadata.json for a given file_id.
    Returns metadata as a dictionary.
    """
    s3_key = f"files/{file_id}/metadata.json"
    response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
    body_text = response["Body"].read().decode("utf-8")
    return json.loads(body_text)


def list_stored_files(s3_client, bucket_name: str) -> list[dict]:
    """
    Scans the S3 bucket for all stored files by looking for metadata.json objects
    under the 'files/' prefix.
    Returns a list of metadata dictionaries sorted by uploaded_at (newest first).
    """
    files = []
    paginator = s3_client.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket_name, Prefix="files/")

    for page in pages:
        contents = page.get("Contents", [])
        for item in contents:
            key = item.get("Key", "")
            # Identify files/<file_id>/metadata.json
            if key.endswith("/metadata.json"):
                parts = key.split("/")
                if len(parts) >= 3:
                    file_id = parts[1]
                    try:
                        meta = download_metadata(s3_client, bucket_name, file_id)
                        files.append(meta)
                    except (ClientError, json.JSONDecodeError):
                        # Continue gracefully if a single file metadata cannot be read
                        continue

    # Sort files by upload timestamp descending (newest first)
    files.sort(key=lambda x: x.get("uploaded_at", ""), reverse=True)
    return files
