import random
import ipaddress
import time
import psycopg2
from ipwhois import IPWhois

# --- Database Configuration ---
DB_NAME = "yourdbname"       # Target database name
DB_USER = "yourusername"     # Database user (must have CREATE DATABASE privileges)
DB_PASSWORD = "yourpassword" # Database password
DB_HOST = "localhost"        # Database host (adjust if needed)
DB_PORT = "5432"             # Default PostgreSQL port

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
        if ip.is_global:
            return ip

def main():
    # Step 1: Create the target database if it doesn't exist.
    create_database()

    # Step 2: Connect to the target database and create the table.
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
        )
        cursor = conn.cursor()
        create_table(cursor, conn)
    except Exception as e:
        print(f"Error connecting to the target database: {e}")
        return

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
