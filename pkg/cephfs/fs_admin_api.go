//go:build !darwin
// +build !darwin

package cephfs

import "github.com/ceph/go-ceph/cephfs/admin"

// fsAdminAPI constrains CephFS admin usage to a small EOS-owned seam.
// This localizes breakage when go-ceph changes APIs.
type fsAdminAPI interface {
	ListVolumes() ([]string, error)
	FetchVolumeInfo(volume string) (*admin.VolInfo, error)
	CreateSubVolume(volume, group, name string, o *admin.SubVolumeOptions) error
	ListSubVolumes(volume, group string) ([]string, error)
	ResizeSubVolume(volume, group, name string, newSize admin.QuotaSize, noShrink bool) (*admin.SubVolumeResizeResult, error)
	RemoveSubVolume(volume, group, name string) error
	CreateSubVolumeSnapshot(volume, group, source, name string) error
	RemoveSubVolumeSnapshot(volume, group, subvolume, name string) error
	ListSubVolumeSnapshots(volume, group, name string) ([]string, error)
	SubVolumeSnapshotInfo(volume, group, subvolume, name string) (*admin.SubVolumeSnapshotInfo, error)
	CloneSubVolumeSnapshot(volume, group, subvolume, snapshot, name string, o *admin.CloneOptions) error
	CloneStatus(volume, group, clone string) (*admin.CloneStatus, error)
	ProtectSubVolumeSnapshot(volume, group, subvolume, name string) error
	UnprotectSubVolumeSnapshot(volume, group, subvolume, name string) error
}

type goCephFSAdminAdapter struct {
	inner *admin.FSAdmin
}

func newFSAdminAdapter(inner *admin.FSAdmin) fsAdminAPI {
	return &goCephFSAdminAdapter{inner: inner}
}

func (a *goCephFSAdminAdapter) ListVolumes() ([]string, error) {
	return a.inner.ListVolumes()
}

func (a *goCephFSAdminAdapter) FetchVolumeInfo(volume string) (*admin.VolInfo, error) {
	return a.inner.FetchVolumeInfo(volume)
}

func (a *goCephFSAdminAdapter) CreateSubVolume(volume, group, name string, o *admin.SubVolumeOptions) error {
	return a.inner.CreateSubVolume(volume, group, name, o)
}

func (a *goCephFSAdminAdapter) ListSubVolumes(volume, group string) ([]string, error) {
	return a.inner.ListSubVolumes(volume, group)
}

func (a *goCephFSAdminAdapter) ResizeSubVolume(volume, group, name string, newSize admin.QuotaSize, noShrink bool) (*admin.SubVolumeResizeResult, error) {
	return a.inner.ResizeSubVolume(volume, group, name, newSize, noShrink)
}

func (a *goCephFSAdminAdapter) RemoveSubVolume(volume, group, name string) error {
	return a.inner.RemoveSubVolume(volume, group, name)
}

func (a *goCephFSAdminAdapter) CreateSubVolumeSnapshot(volume, group, source, name string) error {
	return a.inner.CreateSubVolumeSnapshot(volume, group, source, name)
}

func (a *goCephFSAdminAdapter) RemoveSubVolumeSnapshot(volume, group, subvolume, name string) error {
	return a.inner.RemoveSubVolumeSnapshot(volume, group, subvolume, name)
}

func (a *goCephFSAdminAdapter) ListSubVolumeSnapshots(volume, group, name string) ([]string, error) {
	return a.inner.ListSubVolumeSnapshots(volume, group, name)
}

func (a *goCephFSAdminAdapter) SubVolumeSnapshotInfo(volume, group, subvolume, name string) (*admin.SubVolumeSnapshotInfo, error) {
	return a.inner.SubVolumeSnapshotInfo(volume, group, subvolume, name)
}

func (a *goCephFSAdminAdapter) CloneSubVolumeSnapshot(volume, group, subvolume, snapshot, name string, o *admin.CloneOptions) error {
	return a.inner.CloneSubVolumeSnapshot(volume, group, subvolume, snapshot, name, o)
}

func (a *goCephFSAdminAdapter) CloneStatus(volume, group, clone string) (*admin.CloneStatus, error) {
	return a.inner.CloneStatus(volume, group, clone)
}

func (a *goCephFSAdminAdapter) ProtectSubVolumeSnapshot(volume, group, subvolume, name string) error {
	return a.inner.ProtectSubVolumeSnapshot(volume, group, subvolume, name)
}

func (a *goCephFSAdminAdapter) UnprotectSubVolumeSnapshot(volume, group, subvolume, name string) error {
	return a.inner.UnprotectSubVolumeSnapshot(volume, group, subvolume, name)
}
