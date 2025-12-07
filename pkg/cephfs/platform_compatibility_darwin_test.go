//go:build darwin
// +build darwin

package cephfs

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

// TestCephClientStubMethods exercises stubbed CephClient methods that only
// exist on macOS builds to ensure they return platform errors.
func TestCephClientStubMethods(t *testing.T) {
	rc := testutil.TestContext(t)

	config := &ClientConfig{
		ClusterName: "ceph",
		User:        "admin",
		MonHosts:    []string{"10.0.0.1"},
	}

	client, _ := NewCephClient(rc, config)
	stubClient := &CephClient{}

	err := stubClient.Connect()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	stats, err := stubClient.GetClusterStats()
	assert.Error(t, err)
	assert.Nil(t, stats)

	exists, err := stubClient.VolumeExists(rc, "test")
	assert.Error(t, err)
	assert.False(t, exists)

	volumes, err := stubClient.ListVolumes(rc)
	assert.Error(t, err)
	assert.Nil(t, volumes)

	err = stubClient.CreateVolume(rc, &VolumeCreateOptions{Name: "test"})
	assert.Error(t, err)

	err = stubClient.DeleteVolume(rc, "test", false)
	assert.Error(t, err)

	assert.Nil(t, client, "NewCephClient should return nil client on macOS")
}
