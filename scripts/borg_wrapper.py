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



from borg_wrappers import init_borg_repo, create_borg_backup, list_borg_archives, restore_borg_backup, check_borg_repo

# Initialize a Borg repository
print(init_borg_repo('/path/to/repo'))

# Create a backup
print(create_borg_backup('/path/to/repo', 'backup-2024-08-27', ['/home/user'], exclude_patterns=['/home/user/exclude']))

# List archives in the repository
print(list_borg_archives('/path/to/repo'))

# Restore a backup
print(restore_borg_backup('/path/to/repo', 'backup-2024-08-27', '/home/user/restore'))

# Check the repository for consistency
print(check_borg_repo('/path/to/repo'))
