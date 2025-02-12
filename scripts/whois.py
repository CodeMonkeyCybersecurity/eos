import random
import ipaddress
import time
import psycopg2
from ipwhois import IPWhois

# --- Database Configuration ---
DB_NAME = "yourdbname"
DB_USER = "yourusername"
DB_PASSWORD = "yourpassword"
DB_HOST = "localhost"  # Adjust if your DB is hosted elsewhere

def create_db_table(cursor, conn):
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
    Generate and return a random IPv4 address that is considered global (i.e., public).
    This function loops until a valid global IP is found.
    """
    while True:
        # Generate a random 32-bit integer and convert it to an IPv4 address.
        ip = ipaddress.IPv4Address(random.getrandbits(32))
        if ip.is_global:
            return ip

def main():
    # Connect to PostgreSQL
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST
        )
        cursor = conn.cursor()
        create_db_table(cursor, conn)
    except Exception as e:
        print(f"Error connecting to the database: {e}")
        return

    # Continuously perform WHOIS lookups
    while True:
        ip = get_random_global_ip()
        ip_str = str(ip)
        print(f"Querying WHOIS for IP: {ip_str}")
        try:
            # Perform WHOIS lookup using ipwhois
            obj = IPWhois(ip_str)
            result = obj.lookup_whois()
            owner = result.get('asn_description', 'Unknown')
            print(f"Owner: {owner}")

            # Insert the result into the database.
            cursor.execute(
                "INSERT INTO ip_owners (ip, owner) VALUES (%s, %s) ON CONFLICT (ip) DO NOTHING;",
                (ip_str, owner)
            )
            conn.commit()
        except Exception as e:
            print(f"Error processing IP {ip_str}: {e}")

        # Wait one second before the next query.
        time.sleep(1)

if __name__ == "__main__":
    main()
