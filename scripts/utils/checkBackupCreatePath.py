def check_and_create_path(path):
    """
    Ensure the specified path is a directory. If the path exists (file, symlink, or directory), handle it.
    """
    def backup_path(src_path):
        """Create a timestamped backup of the specified path."""
        try:
            # Generate a timestamp for the backup
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            # Define the backup path
            backup_name = f"{src_path}_{timestamp}.bak"
            # Backup depending on the type
            if os.path.isdir(src_path):
                shutil.copytree(src_path, backup_name)  # Backup the directory
            else:
                shutil.copy2(src_path, backup_name)  # Backup files or symlinks
            logging.info(f"Backed up '{src_path}' to '{backup_name}'.")
            return True
        except Exception as e:
            logging.error(f"Error creating backup for '{src_path}': {e}")
            return False

    try:
        if os.path.exists(path):
            # Handle if the path is a symbolic link
            if os.path.islink(path):
                print(f"Path '{path}' is a symbolic link.")
                print("Options:")
                print("1. Backup and remove symlink, then create directory")
                print("2. Exit the script")

                choice = input("Please enter your choice [1/2]: ").strip() or '1'

                if choice == '1':
                    if backup_path(path):  # Backup the symlink
                        os.unlink(path)  # Remove the symlink
                        os.makedirs(path, exist_ok=True)  # Create the directory
                        logging.info(f"Replaced symlink at '{path}' with a directory.")
                elif choice == '2':
                    logging.info("Exiting script.")
                    sys.exit(0)
                else:
                    logging.warning("Invalid choice. Exiting script.")
                    sys.exit(1)

            # Handle if the path is a file
            elif os.path.isfile(path):
                print(f"Path '{path}' is a file.")
                print("Options:")
                print("1. Backup and remove file, then create directory")
                print("2. Exit the script")

                choice = input("Please enter your choice [1/2]: ").strip() or '1'

                if choice == '1':
                    if backup_path(path):  # Backup the file
                        os.remove(path)  # Remove the file
                        os.makedirs(path, exist_ok=True)  # Create the directory
                        logging.info(f"Replaced file at '{path}' with a directory.")
                elif choice == '2':
                    logging.info("Exiting script.")
                    sys.exit(0)
                else:
                    logging.warning("Invalid choice. Exiting script.")
                    sys.exit(1)

            # Handle if the path is a directory
            elif os.path.isdir(path):
                print(f"Directory '{path}' already exists.")
                print("Options:")
                print("1. Skip and continue (default)")
                print("2. Backup and overwrite the existing directory")
                print("3. Exit the script")

                choice = input("Please enter your choice [1/2/3]: ").strip() or '1'

                if choice == '1':  # Skip and use existing directory
                    logging.info("Continuing with the existing directory.")
                elif choice == '2':  # Backup and overwrite directory
                    if backup_path(path):  # Backup the directory
                        shutil.rmtree(path)  # Remove the directory and its contents
                        os.makedirs(path, exist_ok=True)  # Create a new empty directory
                        logging.info(f"Directory '{path}' has been overwritten.")
                elif choice == '3':  # Exit script
                    logging.info("Exiting script.")
                    sys.exit(0)
                else:
                    logging.warning("Invalid choice. Continuing with the existing directory.")

            else:
                # If the path exists but is not recognized
                logging.error(f"Unrecognized path type at '{path}'. Cannot proceed.")
                sys.exit(1)
        else:
            # Create the path if it does not exist
            os.makedirs(path, exist_ok=True)
            logging.info(f"Directory '{path}' has been created.")

    except PermissionError as e:
        logging.error(f"Permission denied: {e}. Ensure the script has the necessary permissions.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error while handling path '{path}': {e}")
        sys.exit(1)

