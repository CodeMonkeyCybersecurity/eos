import subprocess

def remove_directory_with_shell(path):
    """
    Use the shell command `rm -rf` to delete a directory and its contents.

    :param path: Path to the directory to be deleted.
    """
    try:
        # Execute the command `rm -rf` using subprocess
        subprocess.run(['rm', '-rf', path], check=True)
        print(f"Successfully deleted: {path}")
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while deleting {path}: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Usage
remove_directory_with_shell("<path>")
