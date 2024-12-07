def check_dependencies():
    required_commands = ["apt", "wget", "git"]
    missing_commands = [cmd for cmd in required_commands if not command_exists(cmd)]
    if missing_commands:
        error_exit(f"The following commands are required but not installed: {', '.join(missing_commands)}.\n"
                   f"Please install them using 'sudo apt install {' '.join(missing_commands)}'.")
