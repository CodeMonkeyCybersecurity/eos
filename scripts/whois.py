#!/usr/bin/env python3
import os
import sys
import subprocess
import getpass
import logging

# Set up logging
logging.basicConfig(
    filename='whois.log', 
    level=logging.INFO, 
    format='%(asctime)s %(levelname)s:%(message)s'
)

# --- Check if Running Interactively ---
# If sys.stdout is attached to a TTY, we assume it's running interactively.
if sys.stdout.isatty():
    choice = input(
        "Warning: It appears you are running this script interactively. "
        "It is recommended to run it with nohup (e.g., `nohup python3 whois.py > whois.out 2>&1 &`) so it continues after logout.\n"
        "Do you want to continue running interactively? [Y/n]: "
    )
    if choice.strip().lower() not in ("y", "yes", ""):
        print("Exiting. Please run the script with nohup if you want it to run in the background.")
        sys.exit(0)

# --- Automatic Virtual Environment Setup ---
# Check if we're already in a virtual environment.
# sys.prefix != sys.base_prefix when in a venv.
if os.environ.get("VENV_ACTIVE") != "1" and sys.prefix == sys.base_prefix:
    venv_dir = os.path.join(os.path.dirname(__file__), ".venv")
    
    # Create the virtual environment if it doesn't exist.
    if not os.path.exists(venv_dir):
        print("Creating virtual environment in", venv_dir)
        import venv
        builder = venv.EnvBuilder(with_pip=True)
        builder.create(venv_dir)
    
    # Determine the path to the virtual environment's Python executable.
    python_executable = os.path.join(venv_dir, "bin", "python3")
    if not os.path.exists(python_executable):
        python_executable = os.path.join(venv_dir, "bin", "python")
    
    # Install required packages in the virtual environment.
    print("Installing required packages in the virtual environment...")
    subprocess.check_call([python_executable, "-m", "pip", "install", "ipwhois", "psycopg2-binary"])
    
    # Set an environment variable to avoid re-entering this block and re-launch the script.
    os.environ["VENV_ACTIVE"] = "1"
    print("Re-launching script inside the virtual environment...\n")
    os.execv(python_executable, [python_executable] + sys.argv)

# --- Imports with Graceful Error Handling ---
try:
    import random
    import ipaddress
    import time
    import psycopg2
    from ipwhois import IPWhois
except ModuleNotFoundError as e:
    missing_module = e.name
    print(f"Error: The '{missing_module}' module is not installed.")
    print("Please install all required dependencies. For example, you can run:")
    print("    pip install ipwhois psycopg2-binary")
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred during imports: {e}")
    sys.exit(1)

# --- Prompt for Admin Credentials (for creating the database) ---
print("=== PostgreSQL Admin Credentials ===")
ADMIN_DB = input("Enter admin database name [postgres]: ") or "postgres"
ADMIN_USER = input("Enter admin user [postgres]: ") or "postgres"
ADMIN_PASSWORD = getpass.getpass("Enter admin password: ")
ADMIN_HOST = input("Enter admin host [localhost]: ") or "localhost"
ADMIN_PORT = input("Enter admin port [5432]: ") or "5432"

# --- Prompt for Target Database Configuration ---
print("\n=== Target PostgreSQL Database Configuration ===")
DB_NAME = input("Enter target database name [yourdbname]: ") or "yourdbname"
DB_USER = input("Enter target database user [yourusername]: ") or "yourusername"
DB_PASSWORD = getpass.getpass("Enter target database user's password [yourpassword]: ") or "yourpassword"
DB_HOST = input("Enter target database host [localhost]: ") or "localhost"
DB_PORT = input("Enter target database port [5432]: ") or "5432"

def create_target_user():
    """
    Connects using admin credentials and checks if the target user exists.
    If not, creates the user with the provided password and grants CREATEDB privilege.
    """
    try:
        conn = psycopg2.connect(
            dbname=ADMIN_DB, user=ADMIN_USER, password=ADMIN_PASSWORD, host=ADMIN_HOST, port=ADMIN_PORT
        )
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname=%s;", (DB_USER,))
        exists = cursor.fetchone()
        if not exists:
            print(f"User '{DB_USER}' does not exist. Creating...")
            # Create the user with the given password
            cursor.execute("CREATE USER {} WITH PASSWORD %s;".format(DB_USER), (DB_PASSWORD,))
            # Grant the CREATEDB privilege so the user can own a database
            cursor.execute("ALTER USER {} WITH CREATEDB;".format(DB_USER))
            print(f"User '{DB_USER}' created successfully.")
        else:
            print(f"User '{DB_USER}' already exists.")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error while checking/creating target user: {e}")
        raise

def create_database():
    """
    Connects to the admin database and checks if the target database exists.
    If it doesn't exist, it creates the database with DB_USER as the owner.
    """
    try:
        conn = psycopg2.connect(
            dbname=ADMIN_DB, user=ADMIN_USER, password=ADMIN_PASSWORD, host=ADMIN_HOST, port=ADMIN_PORT
        )
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM pg_database WHERE datname=%s;", (DB_NAME,))
        exists = cursor.fetchone()
        if not exists:
            print(f"Database '{DB_NAME}' does not exist. Creating...")
            cursor.execute(f"CREATE DATABASE {DB_NAME} OWNER {DB_USER};")
            print(f"Database '{DB_NAME}' created successfully.")
        else:
            print(f"Database '{DB_NAME}' already exists.")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error while checking/creating database: {e}")
        raise

def create_table(cursor, conn):
    """Create the ip_owners table if it doesn't exist."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_owners (
            ip inet PRIMARY KEY,
            owner text,
            query_date timestamp DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

def get_random_global_ip():
    """
    Generate and return a random IPv4 address that is global (i.e., public).
    This loops until a valid global IP is found.
    """
    while True:
        ip = ipaddress.IPv4Address(random.getrandbits(32))
        # Ensure the IP is global and not multicast.
        if ip.is_global and not ip.is_multicast:
            return ip

def main():
    # Create the target user if needed (using admin credentials).
    try:
        create_target_user()
    except Exception as e:
        print("Exiting due to target user creation error.")
        sys.exit(1)
        
    # Create the target database if it doesn't exist.
    try:
        create_database()
    except Exception as e:
        print("Exiting due to database creation error.")
        sys.exit(1)

    # Connect to the target database and create the table.
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
        )
        cursor = conn.cursor()
        create_table(cursor, conn)
    except Exception as e:
        print(f"Error connecting to the target database: {e}")
        sys.exit(1)

    # Continuously perform WHOIS lookups for a random global IP.
    while True:
        ip = get_random_global_ip()
        ip_str = str(ip)
        print(f"Querying WHOIS for IP: {ip_str}")
        try:
            obj = IPWhois(ip_str)
            result = obj.lookup_whois()
            owner = result.get('asn_description', 'Unknown')
            print(f"Owner: {owner}")
            cursor.execute(
                "INSERT INTO ip_owners (ip, owner) VALUES (%s, %s) ON CONFLICT (ip) DO NOTHING;",
                (ip_str, owner)
            )
            conn.commit()
        except Exception as e:
            print(f"Error processing IP {ip_str}: {e}")
        # Pause 1 second between queries.
        time.sleep(1)

if __name__ == "__main__":
    main()
