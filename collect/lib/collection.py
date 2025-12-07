import socket
import tarfile
import os
import shutil

def compress(outdir, target_dir_name):
    src_path = os.path.join(outdir, target_dir_name)
    hostname = socket.gethostname()
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Source directory does not exist: {src_path}")
    hostname = socket.gethostname()
    tar_path = os.path.join(outdir, f"{hostname}_{target_dir_name}.tar.gz")

    # Create tar.gz archive
    with tarfile.open(tar_path, "w:gz") as tar:
        # Add the directory, keeping its name inside the archive
        tar.add(src_path, arcname=target_dir_name)

    # Remove the original directory
    shutil.rmtree(src_path)
