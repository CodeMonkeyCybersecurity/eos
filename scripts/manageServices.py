import subprocess
import sys

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

def main():
    if len(sys.argv) < 2:
        print("Usage: services.py [--list-all | --list-active | --logs <service> | --live-logs <service> | --up <service> | --down <service>]")
        sys.exit(1)

    flag = sys.argv[1]

    if flag == '--list-all':
        list_all_services()
    elif flag == '--list-active':
        list_active_services()
    elif flag == '--logs' and len(sys.argv) == 3:
        show_logs(sys.argv[2])
    elif flag == '--live-logs' and len(sys.argv) == 3:
        live_logs(sys.argv[2])
    elif flag == '--up' and len(sys.argv) == 3:
        start_and_enable(sys.argv[2])
    elif flag == '--down' and len(sys.argv) == 3:
        stop_and_disable(sys.argv[2])
    else:
        print("Invalid usage or missing arguments.")
        print("Usage: services.py [--list-all | --list-active | --logs <service> | --live-logs <service> | --up <service> | --down <service>]")
        sys.exit(1)

if __name__ == '__main__':
    main()
