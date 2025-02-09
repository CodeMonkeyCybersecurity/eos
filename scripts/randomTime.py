import random

# Generate a random number between 1 and 100
random_number_day = random.randint(0, 6)
random_number_hour = random.randint(0, 23)
random_number_mins = random.randint(0, 59)

# Dictionary mapping numbers to days of the week
days_of_week = {
    0: "Sunday",
    1: "Monday",
    2: "Tuesday",
    3: "Wednesday",
    4: "Thursday",
    5: "Friday",
    6: "Saturday"
}

# Example: Map a number to a day
day = days_of_week.get(random_number_day, "Invalid day")  # Handles invalid numbers gracefully

print(f"The random time of the week is {random_number_hour:02}:{random_number_mins:02} on {day}.")