check_and_prepare_directory() {
    local dir_path=$1
    local action_on_nonempty=$2  # Accept "prompt", "overwrite", or "exit"
    
    if [ -d "$dir_path" ]; then
        if [ "$(ls -A "$dir_path")" ]; then
            echo "[Warning] Directory $dir_path is not empty."

            case $action_on_nonempty in
                prompt)
                    read -p "Do you want to proceed and overwrite the contents of $dir_path? [y/N]: " response
                    if [[ "$response" =~ ^[Yy]$ ]]; then
                        echo "[Info] Overwriting $dir_path."
                        rm -rf "$dir_path" || error_exit "Failed to remove $dir_path."
                    else
                        error_exit "Aborting script due to non-empty directory: $dir_path."
                    fi
                    ;;
                overwrite)
                    echo "[Info] Overwriting $dir_path."
                    rm -rf "$dir_path" || error_exit "Failed to remove $dir_path."
                    ;;
                exit)
                    error_exit "Directory $dir_path is not empty. Aborting."
                    ;;
                *)
                    error_exit "Invalid action_on_nonempty value: $action_on_nonempty."
                    ;;
            esac
        fi
    fi

    # Create directory if it does not exist
    mkdir -p "$dir_path" || error_exit "Failed to create directory $dir_path."
    echo "[Info] Directory $dir_path is ready."
}
