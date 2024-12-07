def get_valid_user(prompt):
    while True:
        user_input = input(prompt).strip()
        if not user_input:
            logging.error("[Error] Input cannot be empty. Please try again.")
        elif not user_input.isalnum():
            logging.error("[Error] Usernames can only contain letters and numbers. Please try again.")
        else:
            return user_input
