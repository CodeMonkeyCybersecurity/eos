#!/usr/bin/env python3
import os
import sys
import subprocess
import getpass
import logging
import time
import random
import ipaddress
import psycopg2
from ipwhois import IPWhois

# Set up logging
logging.basicConfig(
    filename='whois.log', 
    level=logging.INFO, 
    format='%(asctime)s %(levelname)s:%(message)s'
)

def daemonize():
    """Perform a UNIX double-fork to daemonize the process."""
    try:
        # First fork
        pid = os.fork()
        if pid > 0:
            # Exit parent
            sys.exit(0)
    except OSError as e:
        sys.exit(f"Fork #1 failed: {e}")

    # Decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)

    try:
        # Second fork
        pid = os.fork()
        if pid > 0:
            # Exit from second parent
            sys.exit(0)
    except OSError as e:
        sys.exit(f"Fork #2 failed: {e}")

    # Redirect standard file descriptors to /dev/null
    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null', 'r') as si:
        os.dup2(si.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'a+') as so:
        os.dup2(so.fileno(), sys.stdout.fileno())
    with open('/dev/null', 'a+') as se:
        os.dup2(se.fileno(), sys.stderr.fileno())

# --- Check if running in daemon mode or interactively ---
if "--daemonize" in sys.argv:
    daemonize()
else:
    if sys.stdout.isatty():
        choice = input(
            "Warning: It is recommended to run this script as a daemon.\n"
            "Would you like to daemonize the process now? (Y/n): "
        )
        if choice.strip().lower() in ("y", "yes", ""):
            print("Daemonizing... (exiting the current process)")
            daemonize()
        else:
            print("Continuing interactively. Note: if you log out, the script will stop.")

# --- Automatic Virtual Environment Setup ---
# Check if we're already in a virtual environment.
if os.environ.get("VENV_ACTIVE") != "1" and sys.prefix == sys.base_prefix:
    # Instead of using a relative path (".venv"), use an absolute path.
    venv_dir = '/opt/whois/venv'
    
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
            dbname=ADMIN_DB, user=ADMIN_USER, password=ADMIN_PASSWORD,
            host=ADMIN_HOST, port=ADMIN_PORT
        )
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname=%s;", (DB_USER,))
        exists = cursor.fetchone()
        if not exists:
            print(f"User '{DB_USER}' does not exist. Creating...")
            cursor.execute("CREATE USER {} WITH PASSWORD %s;".format(DB_USER), (DB_PASSWORD,))
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
            dbname=ADMIN_DB, user=ADMIN_USER, password=ADMIN_PASSWORD,
            host=ADMIN_HOST, port=ADMIN_PORT
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
        if ip.is_global and not ip.is_multicast:
            return ip

def main():
    try:
        create_target_user()
    except Exception as e:
        print("Exiting due to target user creation error.")
        sys.exit(1)
        
    try:
        create_database()
    except Exception as e:
        print("Exiting due to database creation error.")
        sys.exit(1)

    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
            host=DB_HOST, port=DB_PORT
        )
        cursor = conn.cursor()
        create_table(cursor, conn)
    except Exception as e:
        print(f"Error connecting to the target database: {e}")
        sys.exit(1)

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
            logging.info(f"Inserted IP {ip_str} with owner: {owner}")
        except Exception as e:
            print(f"Error processing IP {ip_str}: {e}")
            logging.error(f"Error processing IP {ip_str}: {e}")
        time.sleep(1)

if __name__ == "__main__":
    main()
