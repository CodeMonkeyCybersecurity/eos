import os

def cleanup_path():
    # Get the current PATH environment variable
    current_path = os.getenv('PATH', '')

    # Split the PATH into individual directories
    path_dirs = current_path.split(os.pathsep)

    # Remove duplicates by converting to a set, and preserve order by using dict.fromkeys
    cleaned_path = list(dict.fromkeys(path_dirs))

    # Remove non-existent directories and empty paths
    cleaned_path = [p for p in cleaned_path if p and os.path.isdir(p)]

    # Rebuild the PATH string
    new_path = os.pathsep.join(cleaned_path)

    # Print the cleaned-up PATH for review
    print("Cleaned PATH:", new_path)

    # Optionally, you can set the new cleaned-up PATH environment variable like this:
    # os.environ['PATH'] = new_path

    # If you want to save it to a shell configuration file for persistence:
    shell_rc = os.path.expanduser("~/.bashrc")  # or "~/.zshrc" if using zsh
    with open(shell_rc, 'a') as f:
        f.write(f'\nexport PATH="{new_path}"\n')
    
    print(f"New PATH has been added to {shell_rc}. Please run 'source {shell_rc}' or restart your terminal for changes to take effect.")

if __name__ == "__main__":
    cleanup_path()
