def create_borg_backup(repo_path, backup_name, source_paths, exclude_patterns=None):
    """
    Create a backup with Borg.

    :param repo_path: Path to the repository.
    :param backup_name: Name for the backup archive.
    :param source_paths: List of paths to include in the backup.
    :param exclude_patterns: List of exclude patterns (optional).
    :return: Command output or error message.
    """
    try:
        cmd = ['borg', 'create', f'{repo_path}::{backup_name}'] + source_paths
        if exclude_patterns:
            for pattern in exclude_patterns:
                cmd += ['--exclude', pattern]

        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error creating backup: {e.stderr}"

# Usage example:
# print(create_borg_backup('/path/to/repo', 'backup-2024-08-27', ['/home/user'], exclude_patterns=['/home/user/exclude']))
