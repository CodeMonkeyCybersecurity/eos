def command_exists(command):
    """Check if a command exists in the system's PATH."""
    return shutil.which(command) is not None
