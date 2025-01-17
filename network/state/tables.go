package state

import (
	"github.com/safing/portbase/log"
	"github.com/safing/portmaster/network/socket"
)

var (
	tcp4Connections []*socket.ConnectionInfo
	tcp4Listeners   []*socket.BindInfo

	tcp6Connections []*socket.ConnectionInfo
	tcp6Listeners   []*socket.BindInfo

	udp4Binds []*socket.BindInfo

	udp6Binds []*socket.BindInfo
)

func updateTCP4Tables() (connections []*socket.ConnectionInfo, listeners []*socket.BindInfo) {
	var err error
	connections, listeners, err = getTCP4Table()
	if err != nil {
		log.Warningf("state: failed to get TCP4 socket table: %s", err)
		return
	}

	tcp4Connections = connections
	tcp4Listeners = listeners
	return
}

func updateTCP6Tables() (connections []*socket.ConnectionInfo, listeners []*socket.BindInfo) {
	var err error
	connections, listeners, err = getTCP6Table()
	if err != nil {
		log.Warningf("state: failed to get TCP6 socket table: %s", err)
		return
	}

	tcp6Connections = connections
	tcp6Listeners = listeners
	return
}

func updateUDP4Table() (binds []*socket.BindInfo) {
	var err error
	binds, err = getUDP4Table()
	if err != nil {
		log.Warningf("state: failed to get UDP4 socket table: %s", err)
		return
	}

	udp4Binds = binds
	return
}

func updateUDP6Table() (binds []*socket.BindInfo) {
	var err error
	binds, err = getUDP6Table()
	if err != nil {
		log.Warningf("state: failed to get UDP6 socket table: %s", err)
		return
	}

	udp6Binds = binds
	return
}
