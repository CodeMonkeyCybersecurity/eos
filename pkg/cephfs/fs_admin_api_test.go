//go:build !darwin
// +build !darwin

package cephfs

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/ceph/go-ceph/cephfs/admin"
)

func TestGoCephFSAdminAdapter_ImplementsFSAdminAPI(t *testing.T) {
	t.Parallel()

	var _ fsAdminAPI = (*goCephFSAdminAdapter)(nil)
}

func TestCephClientGetFSAdmin_ReturnsNilWhenNoAdapterBound(t *testing.T) {
	t.Parallel()

	client := &CephClient{}
	if got := client.GetFSAdmin(); got != nil {
		t.Fatalf("expected nil fs admin when adapter is unset")
	}
}

func TestCephClientGetFSAdmin_ReturnsWrappedAdminPointer(t *testing.T) {
	t.Parallel()

	raw := &admin.FSAdmin{}
	client := &CephClient{
		fsAdmin: newFSAdminAdapter(raw),
	}

	if got := client.GetFSAdmin(); got != raw {
		t.Fatalf("expected wrapped admin pointer to be returned")
	}
}

func TestCephClientVolumeExists_WithFakeFSAdmin(t *testing.T) {
	t.Parallel()

	client := &CephClient{
		fsAdmin: &fakeFSAdmin{
			volumes: []string{"alpha", "beta"},
		},
	}

	exists, err := client.VolumeExists(testutil.TestRuntimeContext(t), "beta")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Fatalf("expected volume to exist")
	}

	exists, err = client.VolumeExists(testutil.TestRuntimeContext(t), "gamma")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Fatalf("expected volume to be absent")
	}
}

type fakeFSAdmin struct {
	volumes []string
}

func (f *fakeFSAdmin) ListVolumes() ([]string, error) {
	return append([]string(nil), f.volumes...), nil
}

func (f *fakeFSAdmin) FetchVolumeInfo(string) (*admin.VolInfo, error) {
	return nil, nil
}

func (f *fakeFSAdmin) CreateSubVolume(string, string, string, *admin.SubVolumeOptions) error {
	return nil
}

func (f *fakeFSAdmin) ListSubVolumes(string, string) ([]string, error) {
	return nil, nil
}

func (f *fakeFSAdmin) ResizeSubVolume(string, string, string, admin.QuotaSize, bool) (*admin.SubVolumeResizeResult, error) {
	return nil, nil
}

func (f *fakeFSAdmin) RemoveSubVolume(string, string, string) error {
	return nil
}

func (f *fakeFSAdmin) CreateSubVolumeSnapshot(string, string, string, string) error {
	return nil
}

func (f *fakeFSAdmin) RemoveSubVolumeSnapshot(string, string, string, string) error {
	return nil
}

func (f *fakeFSAdmin) ListSubVolumeSnapshots(string, string, string) ([]string, error) {
	return nil, nil
}

func (f *fakeFSAdmin) SubVolumeSnapshotInfo(string, string, string, string) (*admin.SubVolumeSnapshotInfo, error) {
	return nil, nil
}

func (f *fakeFSAdmin) CloneSubVolumeSnapshot(string, string, string, string, string, *admin.CloneOptions) error {
	return nil
}

func (f *fakeFSAdmin) CloneStatus(string, string, string) (*admin.CloneStatus, error) {
	return nil, nil
}

func (f *fakeFSAdmin) ProtectSubVolumeSnapshot(string, string, string, string) error {
	return nil
}

func (f *fakeFSAdmin) UnprotectSubVolumeSnapshot(string, string, string, string) error {
	return nil
}
