// pkg/postgres/types.go
package postgres

import "time"

// KVM represents one libvirt VM with its network info.
type KVM struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Name     string `gorm:"uniqueIndex;not null"`
	MAC      string `gorm:"size:17;not null"`
	Protocol string `gorm:"size:10;not null"`
	IP       string `gorm:"size:45;not null"`
}
