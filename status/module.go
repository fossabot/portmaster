package status

import (
	"github.com/safing/portbase/database"
	"github.com/safing/portbase/log"
	"github.com/safing/portbase/modules"
)

func init() {
	modules.Register("status", nil, start, stop, "base")
}

func start() error {
	var loadedStatus *SystemStatus

	// load status from database
	r, err := statusDB.Get(statusDBKey)
	switch err {
	case nil:
		loadedStatus, err = EnsureSystemStatus(r)
		if err != nil {
			log.Criticalf("status: failed to unwrap system status: %s", err)
			loadedStatus = nil
		}
	case database.ErrNotFound:
		// create new status
	default:
		log.Criticalf("status: failed to load system status: %s", err)
	}

	// activate loaded status, if available
	if loadedStatus != nil {
		status = loadedStatus
	}
	status.Lock()
	defer status.Unlock()

	// load status into atomic getters
	atomicUpdateSelectedSecurityLevel(status.SelectedSecurityLevel)

	// update status
	status.updateThreatMitigationLevel()
	status.autopilot()

	go status.Save()

	return initStatusHook()
}

func stop() error {
	return stopStatusHook()
}
