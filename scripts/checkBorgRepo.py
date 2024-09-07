def check_borg_repo(repo_path):
    """
    Check the consistency of a Borg repository.

    :param repo_path: Path to the repository.
    :return: Command output or error message.
    """
    try:
        result = subprocess.run(
            ['borg', 'check', repo_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error checking repository: {e.stderr}"

# Usage example:
# print(check_borg_repo('/path/to/repo'))
