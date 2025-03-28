#!/usr/bin/env python3
import sys

# Attempt to import required modules. If any module is missing, display an error and exit.
try:
    import psycopg2
    import getpass
except ModuleNotFoundError as e:
    missing_module = e.name
    print(f"Error: The '{missing_module}' module is not installed.")
    print("Please install all required dependencies. For example:")
    print("    pip3 install psycopg2-binary")
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred during imports: {e}")
    sys.exit(1)


def main():
    print("=== PostgreSQL Database Creator ===\n")
    
    # Prompt for admin connection details (the user must have privileges to create users/databases)
    admin_db = "postgres"  # default database for admin tasks
    admin_host = input("Enter admin host (default 'localhost'): ") or "localhost"
    admin_port = input("Enter admin port (default '5432'): ") or "5432"
    admin_user = input("Enter admin username (e.g., 'postgres'): ") or "postgres"
    admin_password = getpass.getpass("Enter admin password: ")
    
    print("\n--- New Database Details ---")
    new_db_name = input("Enter the new database name: ").strip()
    new_db_user = input("Enter the new database username: ").strip()
    new_db_password = getpass.getpass("Enter the new database user's password: ")
    
    try:
        # Connect to the PostgreSQL server using admin credentials.
        conn = psycopg2.connect(
            dbname=admin_db,
            user=admin_user,
            password=admin_password,
            host=admin_host,
            port=admin_port
        )
        conn.autocommit = True  # Allows us to execute CREATE DATABASE outside a transaction
        cur = conn.cursor()

        # Create the new user if it does not already exist.
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s;", (new_db_user,))
        if cur.fetchone():
            print(f"User '{new_db_user}' already exists.")
        else:
            cur.execute("CREATE USER {} WITH PASSWORD %s;".format(new_db_user), (new_db_password,))
            print(f"User '{new_db_user}' created successfully.")

        # Create the new database if it does not already exist.
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s;", (new_db_name,))
        if cur.fetchone():
            print(f"Database '{new_db_name}' already exists.")
        else:
            cur.execute("CREATE DATABASE {} OWNER {};".format(new_db_name, new_db_user))
            print(f"Database '{new_db_name}' created successfully and ownership granted to '{new_db_user}'.")

        # Grant all privileges on the new database to the new user.
        cur.execute("GRANT ALL PRIVILEGES ON DATABASE {} TO {};".format(new_db_name, new_db_user))
        print(f"All privileges on database '{new_db_name}' granted to '{new_db_user}'.")

        # Clean up
        cur.close()
        conn.close()
        print("\nOperation completed successfully.")
        
    except Exception as e:
        print("\nAn error occurred:")
        print(e)
        sys.exit(1)

if __name__ == "__main__":
    main()
