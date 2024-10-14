import subprocess

def list_all_services():
    subprocess.run(['systemctl', 'list-units', '--type=service', '--all'])

def list_active_services():
    subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'])

def show_logs(service_name):
    subprocess.run(['journalctl', '-u', service_name])

def live_logs(service_name):
    subprocess.run(['journalctl', '-u', service_name, '-f'])

def start_and_enable(service_name):
    subprocess.run(['systemctl', 'start', service_name])
    subprocess.run(['systemctl', 'enable', service_name])

def stop_and_disable(service_name):
    subprocess.run(['systemctl', 'stop', service_name])
    subprocess.run(['systemctl', 'disable', service_name])

def manage_services():
    while True:
        print("\nChoose an option (or type 'exit' to quit):")
        print("--list-all: List all services")
        print("--list-active: List active services")
        print("--logs <service>: Show logs for a service")
        print("--live-logs <service>: Stream live logs for a service")
        print("--up <service>: Start and enable a service")
        print("--down <service>: Stop and disable a service")
        
        user_input = input("Enter your choice: ").strip()
        if user_input == 'exit':
            print("Exiting service manager.")
            break

        args = user_input.split()

        if args[0] == '--list-all':
            list_all_services()
        elif args[0] == '--list-active':
            list_active_services()
        elif args[0] == '--logs' and len(args) == 2:
            show_logs(args[1])
        elif args[0] == '--live-logs' and len(args) == 2:
            live_logs(args[1])
        elif args[0] == '--up' and len(args) == 2:
            start_and_enable(args[1])
        elif args[0] == '--down' and len(args) == 2:
            stop_and_disable(args[1])
        else:
            print("Invalid input. Please try again.")

if __name__ == '__main__':
    manage_services()
