"""
app.py - Streamlit Frontend for Secure Cloud Storage.

A clean, secure cloud storage web application built with Streamlit, AWS S3,
and AES-256-GCM encryption.

Features:
1. Upload File: Segments files into 1 MB chunks, encrypts each with AES-256-GCM,
   and uploads chunks and metadata to AWS S3.
2. Download & Decrypt File: Fetches encrypted chunks from S3, verifies authentication tags,
   decrypts each chunk, reconstructs the original file, and delivers it to the user.
3. GitHub: Direct link to the source repository.
"""

from datetime import datetime, timezone
import streamlit as st
from botocore.exceptions import ClientError, BotoCoreError
from cryptography.exceptions import InvalidTag

import encryption
import storage

# ==============================================================================
# PLACEHOLDER: Replace with your GitHub profile or repository URL
# ==============================================================================
GITHUB_URL = "https://github.com/tanmayjadhavaiml/secure-cloud-storage"


def format_size(size_bytes: int) -> str:
    """Formats raw bytes into a human-readable string (B, KB, MB, GB)."""
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024.0 or unit == "GB":
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.2f} GB"


def load_configuration():
    """
    Validates and loads AWS credentials and Master Encryption Key from Streamlit Secrets.
    Returns (s3_client, bucket_name, master_key_bytes) or None on failure.
    """
    if "aws" not in st.secrets or "security" not in st.secrets:
        st.error(
            "Configuration missing! Please create `.streamlit/secrets.toml` "
            "based on `.streamlit/secrets.toml.example`."
        )
        return None, None, None

    aws_cfg = st.secrets["aws"]
    sec_cfg = st.secrets["security"]

    required_aws_fields = ["aws_access_key_id", "aws_secret_access_key", "region_name", "bucket_name"]
    for field in required_aws_fields:
        if field not in aws_cfg or not aws_cfg[field]:
            st.error(f"Missing required AWS secret: `aws.{field}`")
            return None, None, None

    if "master_key" not in sec_cfg or not sec_cfg["master_key"]:
        st.error("Missing required secret: `security.master_key`")
        return None, None, None

    try:
        master_key_bytes = encryption.parse_master_key(sec_cfg["master_key"])
    except ValueError as e:
        st.error(f"Invalid Master Key: {e}")
        return None, None, None

    try:
        s3_client = storage.get_s3_client(
            aws_access_key_id=aws_cfg["aws_access_key_id"],
            aws_secret_access_key=aws_cfg["aws_secret_access_key"],
            region_name=aws_cfg["region_name"],
        )
    except Exception as e:
        st.error(f"Failed to initialize AWS S3 client: {e}")
        return None, None, None

    return s3_client, aws_cfg["bucket_name"], master_key_bytes


def main():
    st.set_page_config(
        page_title="Secure Cloud Storage",
        page_icon="🔒",
        layout="centered",
    )

    st.title("🔒 Secure Cloud Storage")
    st.caption("College Cloud Computing Mini-Project | AES-256-GCM + AWS S3")

    # Sidebar: Navigation and GitHub Link
    st.sidebar.header("Navigation")
    menu_choice = st.sidebar.radio(
        "Select Operation",
        ["Upload File", "Download & Decrypt File"],
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Project Repository")
    st.sidebar.link_button("🌐 Open GitHub", GITHUB_URL, use_container_width=True)

    # Load and validate credentials
    s3_client, bucket_name, master_key_bytes = load_configuration()
    if not s3_client:
        st.stop()

    # --------------------------------------------------------------------------
    # 1. UPLOAD FILE
    # --------------------------------------------------------------------------
    if menu_choice == "Upload File":
        st.subheader("📤 Encrypt and Upload File")
        st.write(
            "Select a file to securely split into 1 MB chunks, encrypt with **AES-256-GCM**, "
            "and store in your private AWS S3 bucket."
        )

        uploaded_file = st.file_uploader("Choose a file to upload", type=None)

        if uploaded_file is not None:
            file_bytes = uploaded_file.getvalue()
            file_size = len(file_bytes)
            num_chunks = max(1, (file_size + encryption.CHUNK_SIZE - 1) // encryption.CHUNK_SIZE) if file_size > 0 else 0

            st.info(
                f"**File Selected:** `{uploaded_file.name}`  \n"
                f"**File Size:** {format_size(file_size)} ({file_size:,} bytes)  \n"
                f"**Calculated Segments:** {num_chunks} chunk(s) (1 MB each)"
            )

            if st.button("Encrypt & Upload to S3", type="primary"):
                try:
                    import uuid

                    file_id = uuid.uuid4().hex
                    salt = encryption.generate_salt()
                    file_key = encryption.derive_file_key(master_key_bytes, salt)
                    chunks = encryption.split_file_into_chunks(file_bytes)
                    total_chunks = len(chunks)

                    progress_bar = st.progress(0.0)
                    status_text = st.empty()

                    metadata_chunks = []

                    if total_chunks == 0:
                        # Empty file handling
                        status_text.text("Processing empty file...")
                        progress_bar.progress(1.0)
                    else:
                        for idx, chunk_bytes in enumerate(chunks):
                            status_text.text(f"Encrypting & uploading chunk {idx + 1}/{total_chunks}...")
                            nonce, ciphertext = encryption.encrypt_chunk(chunk_bytes, file_key)
                            s3_key = storage.upload_chunk(
                                s3_client=s3_client,
                                bucket_name=bucket_name,
                                file_id=file_id,
                                block_index=idx,
                                data=ciphertext,
                            )
                            metadata_chunks.append({
                                "index": idx,
                                "s3_key": s3_key,
                                "nonce": nonce.hex(),
                            })
                            progress_bar.progress((idx + 1) / total_chunks)

                    # Prepare and upload metadata
                    status_text.text("Saving reconstruction metadata to S3...")
                    metadata = {
                        "file_id": file_id,
                        "original_filename": uploaded_file.name,
                        "original_size": file_size,
                        "chunk_size": encryption.CHUNK_SIZE,
                        "total_chunks": total_chunks,
                        "salt": salt.hex(),
                        "chunks": metadata_chunks,
                        "uploaded_at": datetime.now(timezone.utc).isoformat(),
                    }

                    storage.upload_metadata(s3_client, bucket_name, file_id, metadata)
                    status_text.empty()
                    progress_bar.empty()

                    st.success("File encrypted and uploaded successfully!")
                    st.json({
                        "File ID": file_id,
                        "Original Name": uploaded_file.name,
                        "Size": format_size(file_size),
                        "Encrypted Chunks": total_chunks,
                        "S3 Path": f"s3://{bucket_name}/files/{file_id}/",
                        "Encryption": "AES-256-GCM (HKDF-SHA256 derived key)",
                    })

                except (ClientError, BotoCoreError) as aws_err:
                    st.error(f"AWS S3 Error: {aws_err}")
                except Exception as err:
                    st.error(f"Upload failed: {err}")

    # --------------------------------------------------------------------------
    # 2. DOWNLOAD & DECRYPT FILE
    # --------------------------------------------------------------------------
    elif menu_choice == "Download & Decrypt File":
        st.subheader("📥 Download & Decrypt File")
        st.write("Browse stored files, download encrypted blocks, verify cryptographic integrity, and reconstruct the original file.")

        col_refresh, _ = st.columns([1, 4])
        with col_refresh:
            refresh = st.button("🔄 Refresh Files")

        with st.spinner("Fetching stored files from S3..."):
            try:
                stored_files = storage.list_stored_files(s3_client, bucket_name)
            except (ClientError, BotoCoreError) as aws_err:
                st.error(f"Failed to list S3 files: {aws_err}")
                stored_files = []

        if not stored_files:
            st.info("No files currently stored in the S3 bucket.")
        else:
            file_options = {
                f"{f['original_filename']} ({format_size(f['original_size'])}, {f['total_chunks']} chunks) - ID: {f['file_id'][:8]}...": f
                for f in stored_files
            }

            selected_label = st.selectbox("Select a file to retrieve:", list(file_options.keys()))
            selected_meta = file_options[selected_label]

            # Display file metadata
            with st.expander("📄 View File Metadata", expanded=True):
                st.markdown(f"- **Filename:** `{selected_meta['original_filename']}`")
                st.markdown(f"- **File ID:** `{selected_meta['file_id']}`")
                st.markdown(f"- **Original Size:** {format_size(selected_meta['original_size'])} ({selected_meta['original_size']:,} bytes)")
                st.markdown(f"- **Encrypted Blocks:** {selected_meta['total_chunks']}")
                st.markdown(f"- **Uploaded At:** {selected_meta.get('uploaded_at', 'Unknown')}")

            if st.button("Download, Decrypt & Reconstruct", type="primary"):
                try:
                    # 1. Derive file key using stored salt and persistent master key
                    salt = bytes.fromhex(selected_meta["salt"])
                    file_key = encryption.derive_file_key(master_key_bytes, salt)

                    total_chunks = selected_meta["total_chunks"]
                    chunks_meta = sorted(selected_meta.get("chunks", []), key=lambda c: c["index"])

                    decrypted_chunks = []
                    progress_bar = st.progress(0.0)
                    status_text = st.empty()

                    if total_chunks > 0:
                        for idx, chunk_info in enumerate(chunks_meta):
                            status_text.text(f"Downloading & decrypting chunk {idx + 1}/{total_chunks}...")

                            # Download chunk from S3
                            ciphertext = storage.download_chunk(
                                s3_client=s3_client,
                                bucket_name=bucket_name,
                                s3_key=chunk_info["s3_key"],
                            )

                            # Decrypt and authenticate chunk
                            nonce = bytes.fromhex(chunk_info["nonce"])
                            chunk_plaintext = encryption.decrypt_chunk(
                                ciphertext=ciphertext,
                                nonce=nonce,
                                file_key=file_key,
                            )
                            decrypted_chunks.append(chunk_plaintext)
                            progress_bar.progress((idx + 1) / total_chunks)

                    # Reconstruct original file
                    reconstructed_bytes = encryption.reconstruct_file(decrypted_chunks)
                    status_text.empty()
                    progress_bar.empty()

                    # Validate reconstructed size
                    if len(reconstructed_bytes) != selected_meta["original_size"]:
                        st.error("Integrity Error: Reconstructed file size does not match original size.")
                    else:
                        st.success("File downloaded, verified, and decrypted successfully!")
                        st.download_button(
                            label=f"💾 Save '{selected_meta['original_filename']}'",
                            data=reconstructed_bytes,
                            file_name=selected_meta["original_filename"],
                            mime="application/octet-stream",
                        )

                except InvalidTag:
                    st.error(
                        "Decryption Error: AES-GCM authentication failed! "
                        "The data may have been altered or the master key does not match."
                    )
                except (ClientError, BotoCoreError) as aws_err:
                    st.error(f"AWS S3 Error: {aws_err}")
                except Exception as err:
                    st.error(f"Decryption failed: {err}")


if __name__ == "__main__":
    main()
