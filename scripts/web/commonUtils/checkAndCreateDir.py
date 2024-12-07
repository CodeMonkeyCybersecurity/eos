def check_and_create_directory(dir_path):
    """Ensure that the specified path is a directory. If it exists, handle according to user choice."""
    if os.path.islink(dir_path):
        os.unlink(dir_path)
        logging.info(f"Removed symlink at '{dir_path}'.")

    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
        logging.info(f"Directory '{dir_path}' has been created.")
    elif os.path.isdir(dir_path):
        print(f"Directory '{dir_path}' already exists.")
        print("Options:")
        print("1. Skip and continue (default)")
        print("2. Overwrite the existing directory")
        print("3. Exit the script")

        choice = input("Please enter your choice [1/2/3]: ").strip() or '1'

        if choice == '1':
            logging.info("Continuing with the existing directory.")
        elif choice == '2':
            try:
                shutil.rmtree(dir_path)
                os.makedirs(dir_path)
                logging.info(f"Directory '{dir_path}' has been overwritten.")
            except Exception as e:
                logging.error(f"Failed to overwrite directory '{dir_path}': {e}")
                sys.exit(1)
        elif choice == '3':
            logging.info("Exiting script.")
            sys.exit(0)
        else:
            logging.warning("Invalid choice. Continuing with the existing directory.")
    else:
        # Path exists but is not a directory
        logging.error(f"A file with the name '{dir_path}' exists.")
        logging.error("Cannot proceed as a file exists with the same name as the desired directory.")
        sys.exit(1)
