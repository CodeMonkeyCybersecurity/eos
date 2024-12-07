def run_command(command, error_message):
    logging.debug(f"Running command: {command}")
    # Run the command interactively
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        logging.error(f"Command failed.")
        error_exit(f"{error_message}")
    logging.debug("Command succeeded.")
