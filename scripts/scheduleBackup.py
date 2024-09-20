import subprocess
import re

def get_backup_time():
    """Ask the user for the backup time."""
    print("Enter the time of day you want the backup to run (HH:MM, 24-hour format).")
    while True:
        backup_time = input("Backup time (HH:MM): ")
        if re.match(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$', backup_time):
            return backup_time
        else:
            print("Invalid time format. Please enter the time in HH:MM format (24-hour).")

def convert_to_crontab_format(backup_time):
    """Convert HH:MM format to crontab format."""
    hours, minutes = backup_time.split(":")
    return f"{minutes} {hours} * * *"

def append_to_crontab(crontab_entry):
    """Append the new backup schedule to crontab."""
    try:
        # Get the current crontab
        current_crontab = subprocess.run(['crontab', '-l'], check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError:
        # If no crontab exists, proceed with an empty one
        current_crontab = ""

    # Add the new entry for backup
    full_crontab = current_crontab + crontab_entry + "\n"
    
    # Write the updated crontab back
    try:
        process = subprocess.run(['crontab', '-'], input=full_crontab, text=True, check=True)
        return process.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Failed to update crontab: {e}")
        return False

def validate_crontab():
    """Check if the crontab entry is valid."""
    try:
        subprocess.run(['crontab', '-l'], check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error validating crontab: {e.stderr}")
        return False

def troubleshoot():
    """Provide troubleshooting options."""
    print("It seems there was an issue adding the crontab entry.")
    print("Here are a few things you can try:")
    print("1. Make sure crontab is installed and you have the necessary permissions.")
    print("2. Check the syntax of your crontab entries using `crontab -l`.")
    print("3. Manually add the crontab entry with `crontab -e`.")

def main():
    backup_time = get_backup_time()
    cron_format = convert_to_crontab_format(backup_time)
    command = "sudo python3 /home/henry/Eos/scripts/borgWrapper.py --backup"
    
    # Append to crontab
    crontab_entry = f"{cron_format} {command}"
    print(f"Adding the following entry to crontab: {crontab_entry}")
    
    if append_to_crontab(crontab_entry):
        print("Crontab entry added successfully.")
    else:
        print("Failed to add crontab entry.")
        troubleshoot()
        return

    # Validate the crontab entry
    if validate_crontab():
        print("Crontab syntax is correct. Backup scheduled successfully!")
    else:
        troubleshoot()

if __name__ == "__main__":
    main()
