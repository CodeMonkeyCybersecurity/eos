import shutil
import os

def remove_directory(path):
    """
    Recursively and forcefully delete a directory and its contents.

    :param path: Path to the directory to be deleted.
    """
    if os.path.exists(path):
        try:
            shutil.rmtree(path)
            print(f"Successfully deleted: {path}")
        except Exception as e:
            print(f"Error while deleting {path}: {e}")
    else:
        print(f"Path does not exist: {path}")

# Usage
remove_directory("<path>")
