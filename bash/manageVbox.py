import subprocess

class VirtualBoxManager:
    def __init__(self):
        self.vboxmanage_cmd = "VBoxManage"
    
    def run_command(self, *args):
        """Helper function to run VirtualBox CLI commands."""
        try:
            result = subprocess.run([self.vboxmanage_cmd] + list(args), capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                print(f"Error: {result.stderr.strip()}")
                return None
        except FileNotFoundError:
            print("Error: VBoxManage command not found. Make sure VirtualBox is installed and VBoxManage is in your PATH.")
            return None

    def list_vms(self):
        """List all virtual machines."""
        return self.run_command("list", "vms")

    def list_running_vms(self):
        """List all running virtual machines."""
        return self.run_command("list", "runningvms")

    def start_vm(self, vm_name):
        """Start a virtual machine."""
        return self.run_command("startvm", vm_name, "--type", "headless")

    def stop_vm(self, vm_name):
        """Stop a virtual machine."""
        return self.run_command("controlvm", vm_name, "acpipowerbutton")

    def power_off_vm(self, vm_name):
        """Power off a virtual machine."""
        return self.run_command("controlvm", vm_name, "poweroff")

    def create_vm(self, vm_name, os_type):
        """Create a new virtual machine."""
        return self.run_command("createvm", "--name", vm_name, "--ostype", os_type, "--register")

    def delete_vm(self, vm_name):
        """Delete a virtual machine."""
        return self.run_command("unregistervm", vm_name, "--delete")

    def take_snapshot(self, vm_name, snapshot_name):
        """Take a snapshot of a virtual machine."""
        return self.run_command("snapshot", vm_name, "take", snapshot_name)

    def restore_snapshot(self, vm_name, snapshot_name):
        """Restore a virtual machine to a specific snapshot."""
        return self.run_command("snapshot", vm_name, "restore", snapshot_name)

    def show_vm_info(self, vm_name):
        """Show detailed information about a virtual machine."""
        return self.run_command("showvminfo", vm_name)

if __name__ == "__main__":
    vbox = VirtualBoxManager()
    
    # Example usage:
    print("Available VMs:")
    print(vbox.list_vms())

    # Uncomment the following lines to perform specific actions.
    # Example: Start a VM
    # print(vbox.start_vm("Your_VM_Name"))

    # Example: Stop a VM
    # print(vbox.stop_vm("Your_VM_Name"))

    # Example: Create a new VM
    # print(vbox.create_vm("New_VM", "Ubuntu_64"))

    # Example: Delete a VM
    # print(vbox.delete_vm("Your_VM_Name"))

    # Example: Take a snapshot
    # print(vbox.take_snapshot("Your_VM_Name", "Snapshot_1"))

    # Example: Restore a snapshot
    # print(vbox.restore_snapshot("Your_VM_Name", "Snapshot_1"))
