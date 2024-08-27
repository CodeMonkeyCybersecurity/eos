import subprocess

def init_borg_repo(repo_path, encryption='none'):
    """
    Initialize a new Borg repository.

    :param repo_path: Path to the repository.
    :param encryption: Encryption mode, default is 'none'.
    :return: Command output or error message.
    """
    try:
        result = subprocess.run(
            ['borg', 'init', '--encryption', encryption, repo_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error initializing repository: {e.stderr}"

# Usage example:
# print(init_borg_repo('/path/to/repo'))
