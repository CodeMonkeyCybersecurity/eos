def list_borg_archives(repo_path):
    """
    List all archives in a Borg repository.

    :param repo_path: Path to the repository.
    :return: List of archives or an error message.
    """
    try:
        result = subprocess.run(
            ['borg', 'list', repo_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error listing archives: {e.stderr}"

# Usage example:
# print(list_borg_archives('/path/to/repo'))
