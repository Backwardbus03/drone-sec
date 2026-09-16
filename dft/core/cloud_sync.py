import os
from pathlib import Path
import logging
import mimetypes

logger = logging.getLogger("dft.cloud_sync")

_SUPABASE_CLIENT = None
BUCKET_NAME = "dft-vault"

def get_supabase():
    global _SUPABASE_CLIENT
    if _SUPABASE_CLIENT:
        return _SUPABASE_CLIENT
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    if not url or not key:
        return None
    try:
        from supabase import create_client
        _SUPABASE_CLIENT = create_client(url, key)
        return _SUPABASE_CLIENT
    except Exception as e:
        logger.error(f"Failed to initialize Supabase client: {e}")
        return None


def upload_file_to_cloud(local_path: Path, base_dir: Path):
    """Uploads a single local file to Supabase Storage."""
    client = get_supabase()
    if not client:
        return
    
    if not local_path.exists() or not local_path.is_file():
        return
        
    try:
        # Calculate relative path to use as object key
        rel_path = str(local_path.relative_to(base_dir)).replace("\\", "/")
        
        # Determine content type
        content_type, _ = mimetypes.guess_type(str(local_path))
        if not content_type:
            content_type = "application/octet-stream"
            
        with open(local_path, "rb") as f:
            file_bytes = f.read()
            
        # Supabase storage doesn't have an "upsert" that works cleanly in all SDK versions,
        # so we try to update first, and if it fails (doesn't exist), we upload.
        try:
            client.storage.from_(BUCKET_NAME).update(rel_path, file_bytes, {"content-type": content_type})
        except Exception:
            try:
                client.storage.from_(BUCKET_NAME).upload(rel_path, file_bytes, {"content-type": content_type})
            except Exception as inner_e:
                logger.error(f"Failed to upload {rel_path}: {inner_e}")
                
    except Exception as e:
        logger.error(f"Cloud upload error for {local_path}: {e}")


def _recursive_download(client, current_cloud_path: str, local_base: Path):
    """Recursively downloads a folder from Supabase Storage."""
    try:
        items = client.storage.from_(BUCKET_NAME).list(current_cloud_path)
        for item in items:
            item_name = item.get("name")
            if not item_name or item_name == ".emptyFolderPlaceholder":
                continue
                
            # If it has no 'id' or metadata, it might be a folder in some SDK versions,
            # but usually Supabase returns folders with metadata if there are files inside.
            # A reliable check is whether we can download it.
            cloud_item_path = f"{current_cloud_path}/{item_name}" if current_cloud_path else item_name
            
            # Check if it's a file by looking at metadata
            if item.get("metadata"):
                # It's a file
                try:
                    local_file = local_base / cloud_item_path
                    local_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    # If file already exists and size matches, skip download
                    cloud_size = item.get("metadata", {}).get("size")
                    if local_file.exists() and cloud_size is not None and local_file.stat().st_size == cloud_size:
                        continue

                    # If file exists and is read-only (evidence protection), make writable before updating
                    if local_file.exists():
                        try:
                            import stat
                            os.chmod(local_file, stat.S_IWRITE)
                        except Exception:
                            pass
                    
                    res = client.storage.from_(BUCKET_NAME).download(cloud_item_path)
                    with open(local_file, "wb") as f:
                        f.write(res)
                except Exception as file_err:
                    logger.warning(f"Could not sync file {cloud_item_path}: {file_err}")
            else:
                # It's a folder, recurse
                _recursive_download(client, cloud_item_path, local_base)
    except Exception as e:
        logger.error(f"Error listing {current_cloud_path}: {e}")


def sync_vault_from_cloud(local_base: Path):
    """
    Downloads the entire vault from Supabase Storage to the local ephemeral disk.
    Called on startup to rehydrate data.
    """
    client = get_supabase()
    if not client:
        logger.warning("No Supabase credentials. Cloud sync disabled.")
        return
        
    logger.info("Syncing forensic vault from Supabase cloud...")
    try:
        # Check if bucket exists, create if not
        buckets = client.storage.list_buckets()
        if not any(b.name == BUCKET_NAME for b in buckets):
            client.storage.create_bucket(BUCKET_NAME, options={"public": False})
            logger.info(f"Created new Supabase bucket: {BUCKET_NAME}")
            return # Bucket is empty anyway
            
        local_base.mkdir(parents=True, exist_ok=True)
        _recursive_download(client, "", local_base)
        logger.info("Cloud sync complete.")
        
    except Exception as e:
        logger.error(f"Failed to sync vault from cloud: {e}")


def delete_case_from_cloud(case_id: str):
    """Deletes all files for a case from Supabase Storage."""
    client = get_supabase()
    if not client:
        return
        
    try:
        # Recursively list all files with prefix case_id
        def list_all_files(prefix=""):
            files = []
            items = client.storage.from_(BUCKET_NAME).list(prefix)
            for item in items:
                name = item.get("name")
                if not name: continue
                path = f"{prefix}/{name}" if prefix else name
                if item.get("metadata"):
                    files.append(path)
                else:
                    files.extend(list_all_files(path))
            return files
            
        case_files = list_all_files(case_id)
        if case_files:
            client.storage.from_(BUCKET_NAME).remove(case_files)
    except Exception as e:
        logger.error(f"Failed to delete case {case_id} from cloud: {e}")


def wipe_cloud_vault():
    """Nuclear wipe of the entire cloud bucket."""
    client = get_supabase()
    if not client:
        return
    try:
        # It's easier to empty the bucket and recreate it
        client.storage.empty_bucket(BUCKET_NAME)
    except Exception as e:
        logger.error(f"Failed to wipe cloud vault: {e}")
