def add_official_deb_src():
    """
    Add official Ubuntu deb-src entries to /etc/apt/sources.list.d/ubuntu.sources, ensuring no duplicates.
    """
    ubuntu_codename = get_ubuntu_codename()
    sources_file = "/etc/apt/sources.list.d/ubuntu.sources"
    deb_src_content = prepare_deb_src_entries(ubuntu_codename)

    try:
        # Read existing content if the file exists
        if os.path.exists(sources_file):
            with open(sources_file, "r") as file:
                existing_content = file.read()
        else:
            existing_content = ""
            # Ensure the directory exists
            os.makedirs(os.path.dirname(sources_file), exist_ok=True)
            logging.info(f"Created directory {os.path.dirname(sources_file)} for sources file.")

        # Check if the deb-src entries are already present
        if deb_src_content in existing_content:
            logging.info("deb-src entries already exist in ubuntu.sources. Skipping addition.")
            return

        # Append deb-src entries to the file
        with open(sources_file, "a") as file:
            logging.info("Adding deb-src entries to ubuntu.sources.")
            # Add a separator if the file is not empty
            if existing_content.strip():
                file.write("\n\n")
            file.write(deb_src_content + "\n")
        logging.info("deb-src entries added successfully.")

        # Update package list
        run_command("apt update", "Failed to update package list.")
    except Exception as e:
        logging.error(f"Failed to add deb-src entries: {e}")
        raise

