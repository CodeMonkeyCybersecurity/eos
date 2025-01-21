import subprocess

def list_cron_jobs():
    """List all current cron jobs."""
    result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
    if result.returncode != 0:
        print("No crontab set for this user.")
    else:
        print(result.stdout)

def add_cron_job(job):
    """Add a new cron job."""
    result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
    if result.returncode != 0:
        cron_jobs = job + '\n'
    else:
        cron_jobs = result.stdout + job + '\n'
    
    process = subprocess.run(['crontab', '-'], input=cron_jobs, text=True)
    if process.returncode == 0:
        print("Cron job added successfully.")
    else:
        print("Failed to add cron job.")

def remove_cron_job(job):
    """Remove a specific cron job."""
    result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
    if result.returncode != 0:
        print("No crontab set for this user.")
        return
    
    cron_jobs = result.stdout.splitlines()
    if job in cron_jobs:
        cron_jobs.remove(job)
        cron_jobs = '\n'.join(cron_jobs) + '\n'
        process = subprocess.run(['crontab', '-'], input=cron_jobs, text=True)
        if process.returncode == 0:
            print("Cron job removed successfully.")
        else:
            print("Failed to remove cron job.")
    else:
        print("Cron job not found.")

def clear_cron_jobs():
    """Clear all cron jobs."""
    process = subprocess.run(['crontab', '-r'])
    if process.returncode == 0:
        print("All cron jobs cleared.")
    else:
        print("Failed to clear cron jobs or no jobs to clear.")

def main():
    while True:
        print("\nCrontab Manager")
        print("1. List all cron jobs")
        print("2. Add a new cron job")
        print("3. Remove a cron job")
        print("4. Clear all cron jobs")
        print("5. Exit")
        
        choice = input("Select an option (1-5): ")
        
        if choice == '1':
            list_cron_jobs()
        elif choice == '2':
            job = input("Enter the cron job (e.g., '* * * * * /path/to/script.sh'): ")
            add_cron_job(job)
        elif choice == '3':
            job = input("Enter the exact cron job to remove: ")
            remove_cron_job(job)
        elif choice == '4':
            clear_cron_jobs()
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
