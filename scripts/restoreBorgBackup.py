def restore_borg_backup(repo_path, archive_name, target_path, restore_paths=None):
    """
    Restore a Borg backup.

    :param repo_path: Path to the repository.
    :param archive_name: Name of the archive to restore.
    :param target_path: Path where to restore the files.
    :param restore_paths: Specific paths within the archive to restore (optional).
    :return: Command output or error message.
    """
    try:
        cmd = ['borg', 'extract', f'{repo_path}::{archive_name}', '--destination', target_path]
        if restore_paths:
            cmd += restore_paths

        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error restoring backup: {e.stderr}"

# Usage example:
# print(restore_borg_backup('/path/to/repo', 'backup-2024-08-27', '/home/user/restore'))
