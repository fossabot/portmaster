package status

import (
	"github.com/safing/portbase/config"
)

type (
	// SecurityLevelOption defines the returned function by ConfigIsActive.
	SecurityLevelOption func(minSecurityLevel uint8) bool
)

func max(a, b uint8) uint8 {
	if a > b {
		return a
	}
	return b
}

// ConfigIsActive returns whether the given security level dependent config option is on or off.
func ConfigIsActive(name string) SecurityLevelOption {
	activeAtLevel := config.GetAsInt(name, int64(SecurityLevelsAll))
	return func(minSecurityLevel uint8) bool {
		return uint8(activeAtLevel())&max(ActiveSecurityLevel(), minSecurityLevel) > 0
	}
}

// ConfigIsActiveConcurrent returns whether the given security level dependent config option is on or off and is concurrency safe.
func ConfigIsActiveConcurrent(name string) SecurityLevelOption {
	activeAtLevel := config.Concurrent.GetAsInt(name, int64(SecurityLevelsAll))
	return func(minSecurityLevel uint8) bool {
		return uint8(activeAtLevel())&max(ActiveSecurityLevel(), minSecurityLevel) > 0
	}
}
