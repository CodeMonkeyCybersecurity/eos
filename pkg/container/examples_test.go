// pkg/container/examples_test.go
// Examples demonstrating the unified Docker SDK usage

package container_test

import (
	"context"
	"fmt"
	"log"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/container"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// Example_basicUsage demonstrates basic container operations
func Example_basicUsage() {
	// Create runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	// Create Docker manager
	manager, err := container.NewManager(rc)
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()
	
	// List all containers
	containers, err := manager.ListAll(rc.Ctx)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Found %d containers\n", len(containers))
	for _, c := range containers {
		fmt.Printf("  - %s (%s): %s\n", c.Name, c.ShortID(), c.State)
	}
}

// Example_composeDiscovery demonstrates Docker Compose service discovery
func Example_composeDiscovery() {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	manager, err := container.NewManager(rc)
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()
	
	// Find Mattermost service (works with Compose v1 and v2)
	containers, err := manager.FindByService(rc.Ctx, "mattermost")
	if err != nil {
		log.Fatal(err)
	}
	
	if len(containers) == 0 {
		fmt.Println("Mattermost service not found")
		return
	}
	
	c := containers[0]
	fmt.Printf("Found Mattermost container:\n")
	fmt.Printf("  ID: %s\n", c.ShortID())
	fmt.Printf("  Name: %s\n", c.Name)
	fmt.Printf("  State: %s\n", c.Status)
	fmt.Printf("  Compose Project: %s\n", c.GetComposeProject())
	fmt.Printf("  Compose Service: %s\n", c.GetComposeService())
}

// Example_containerLifecycle demonstrates container lifecycle operations
func Example_containerLifecycle() {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	manager, err := container.NewManager(rc)
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()
	
	// Find container by name
	c, err := manager.FindByName(rc.Ctx, "mattermost")
	if err != nil {
		log.Fatal(err)
	}
	
	// Stop container
	if c.IsRunning() {
		fmt.Println("Stopping container...")
		err = manager.Stop(rc.Ctx, c.ID, 30)
		if err != nil {
			log.Fatal(err)
		}
	}
	
	// Start container
	fmt.Println("Starting container...")
	err = manager.Start(rc.Ctx, c.ID)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Println("Container restarted successfully")
}

// Example_projectDiscovery demonstrates finding all containers in a Compose project
func Example_projectDiscovery() {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	manager, err := container.NewManager(rc)
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()
	
	// Find all containers in the "docker" project
	containers, err := manager.FindByProject(rc.Ctx, "docker")
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Found %d containers in 'docker' project:\n", len(containers))
	for _, c := range containers {
		fmt.Printf("  - %s (service: %s): %s\n", c.Name, c.GetComposeService(), c.Status)
	}
}

// Example_logs demonstrates retrieving container logs
func Example_logs() {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	manager, err := container.NewManager(rc)
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()
	
	// Find container
	c, err := manager.FindByName(rc.Ctx, "mattermost")
	if err != nil {
		log.Fatal(err)
	}
	
	// Get last 50 lines of logs
	logOptions := container.LogOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       "50",
		Timestamps: true,
	}
	
	logs, err := manager.Logs(rc.Ctx, c.ID, logOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer logs.Close()
	
	fmt.Println("Container logs retrieved successfully")
}

// Example_labelBasedDiscovery demonstrates custom label-based discovery
func Example_labelBasedDiscovery() {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	manager, err := container.NewManager(rc)
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()
	
	// Find containers with custom labels
	labels := map[string]string{
		"app":         "web",
		"environment": "production",
	}
	
	containers, err := manager.FindByLabels(rc.Ctx, labels)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Found %d containers matching labels\n", len(containers))
}

// Example_dockerInfo demonstrates getting Docker system information
func Example_dockerInfo() {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	manager, err := container.NewManager(rc)
	if err != nil {
		log.Fatal(err)
	}
	defer manager.Close()
	
	// Get Docker system info
	info, err := manager.Info(rc.Ctx)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Docker Info:\n")
	fmt.Printf("  Version: %s\n", info.ServerVersion)
	fmt.Printf("  OS: %s\n", info.OperatingSystem)
	fmt.Printf("  Architecture: %s\n", info.Architecture)
	fmt.Printf("  CPUs: %d\n", info.NCPU)
	fmt.Printf("  Total Containers: %d\n", info.Containers)
	fmt.Printf("  Running: %d\n", info.ContainersRunning)
	fmt.Printf("  Stopped: %d\n", info.ContainersStopped)
	fmt.Printf("  Images: %d\n", info.Images)
}
