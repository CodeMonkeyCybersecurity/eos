#!/usr/bin/env python3
import os
import sys
import subprocess
import getpass

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

# --- Prompt for Database Configuration ---
print("=== PostgreSQL Database Configuration ===")
DB_NAME = input("Enter target database name [yourdbname]: ") or "yourdbname"
DB_USER = input("Enter database user [yourusername]: ") or "yourusername"
DB_PASSWORD = getpass.getpass("Enter database password [yourpassword]: ") or "yourpassword"
DB_HOST = input("Enter database host [localhost]: ") or "localhost"
DB_PORT = input("Enter database port [5432]: ") or "5432"

def create_database():
    """
    Connects to the default 'postgres' database and checks if the target database exists.
    If it doesn't exist, it creates the database.
    """
    try:
        # Connect to the default database
        conn = psycopg2.connect(
            dbname="postgres", user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
        )
        conn.autocommit = True  # Needed to execute CREATE DATABASE outside a transaction
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM pg_database WHERE datname=%s;", (DB_NAME,))
        exists = cursor.fetchone()
        if not exists:
            print(f"Database '{DB_NAME}' does not exist. Creating...")
            cursor.execute(f"CREATE DATABASE {DB_NAME};")
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
    # Step 1: Create the target database if it doesn't exist.
    try:
        create_database()
    except Exception as e:
        print("Exiting due to database creation error.")
        sys.exit(1)

    # Step 2: Connect to the target database and create the table.
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
        )
        cursor = conn.cursor()
        create_table(cursor, conn)
    except Exception as e:
        print(f"Error connecting to the target database: {e}")
        sys.exit(1)

    # Step 3: Continuously perform WHOIS lookups for a random global IP.
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
