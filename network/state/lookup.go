package state

import (
	"errors"
	"sync"
	"time"

	"github.com/safing/portmaster/network/netutils"
	"github.com/safing/portmaster/network/packet"
	"github.com/safing/portmaster/network/socket"
)

// - TCP
//   - Outbound: Match listeners (in!), then connections (out!)
//   - Inbound: Match listeners (in!), then connections (out!)
//   - Clean via connections
// - UDP
//   - Any connection: match specific local address or zero IP
//   - In or out: save direction of first packet:
//     - map[<local udp bind ip+port>]map[<remote ip+port>]{direction, lastSeen}
//       - only clean if <local udp bind ip+port> is removed by OS
//       - limit <remote ip+port> to 256 entries?
//       - clean <remote ip+port> after 72hrs?
//       - switch direction to outbound if outbound packet is seen?
// - IP: Unidentified Process

// Errors
var (
	ErrConnectionNotFound = errors.New("could not find connection in system state tables")
	ErrPIDNotFound        = errors.New("could not find pid for socket inode")
)

var (
	tcp4Lock sync.Mutex
	tcp6Lock sync.Mutex
	udp4Lock sync.Mutex
	udp6Lock sync.Mutex

	baseWaitTime = 3 * time.Millisecond
)

// Lookup looks for the given connection in the system state tables and returns the PID of the associated process and whether the connection is inbound.
func Lookup(pktInfo *packet.Info) (pid int, inbound bool, err error) {
	// auto-detect version
	if pktInfo.Version == 0 {
		if ip := pktInfo.LocalIP().To4(); ip != nil {
			pktInfo.Version = packet.IPv4
		} else {
			pktInfo.Version = packet.IPv6
		}
	}

	switch {
	case pktInfo.Version == packet.IPv4 && pktInfo.Protocol == packet.TCP:
		tcp4Lock.Lock()
		defer tcp4Lock.Unlock()
		return searchTCP(tcp4Connections, tcp4Listeners, updateTCP4Tables, pktInfo)

	case pktInfo.Version == packet.IPv6 && pktInfo.Protocol == packet.TCP:
		tcp6Lock.Lock()
		defer tcp6Lock.Unlock()
		return searchTCP(tcp6Connections, tcp6Listeners, updateTCP6Tables, pktInfo)

	case pktInfo.Version == packet.IPv4 && pktInfo.Protocol == packet.UDP:
		udp4Lock.Lock()
		defer udp4Lock.Unlock()
		return searchUDP(udp4Binds, udp4States, updateUDP4Table, pktInfo)

	case pktInfo.Version == packet.IPv6 && pktInfo.Protocol == packet.UDP:
		udp6Lock.Lock()
		defer udp6Lock.Unlock()
		return searchUDP(udp6Binds, udp6States, updateUDP6Table, pktInfo)

	default:
		return socket.UnidentifiedProcessID, false, errors.New("unsupported protocol for finding process")
	}
}

func searchTCP(
	connections []*socket.ConnectionInfo,
	listeners []*socket.BindInfo,
	updateTables func() ([]*socket.ConnectionInfo, []*socket.BindInfo),
	pktInfo *packet.Info,
) (
	pid int,
	inbound bool,
	err error,
) {

	localIP := pktInfo.LocalIP()
	localPort := pktInfo.LocalPort()

	// search until we find something
	for i := 0; i < 7; i++ {
		// always search listeners first
		for _, socketInfo := range listeners {
			if localPort == socketInfo.Local.Port &&
				(socketInfo.Local.IP[0] == 0 || localIP.Equal(socketInfo.Local.IP)) {
				return checkBindPID(socketInfo, true)
			}
		}

		// search connections
		for _, socketInfo := range connections {
			if localPort == socketInfo.Local.Port &&
				localIP.Equal(socketInfo.Local.IP) {
				return checkConnectionPID(socketInfo, false)
			}
		}

		// we found nothing, we could have been too fast, give the kernel some time to think
		// back off timer: with 3ms baseWaitTime: 3, 6, 9, 12, 15, 18, 21ms - 84ms in total
		time.Sleep(time.Duration(i+1) * baseWaitTime)

		// refetch lists
		connections, listeners = updateTables()
	}

	return socket.UnidentifiedProcessID, false, ErrConnectionNotFound
}

func searchUDP(
	binds []*socket.BindInfo,
	udpStates map[string]map[string]*udpState,
	updateTable func() []*socket.BindInfo,
	pktInfo *packet.Info,
) (
	pid int,
	inbound bool,
	err error,
) {

	localIP := pktInfo.LocalIP()
	localPort := pktInfo.LocalPort()

	isInboundMulticast := pktInfo.Inbound && netutils.ClassifyIP(localIP) == netutils.LocalMulticast
	// TODO: Currently broadcast/multicast scopes are not checked, so we might
	// attribute an incoming broadcast/multicast packet to the wrong process if
	// there are multiple processes listening on the same local port, but
	// binding to different addresses. This highly unusual for clients.

	// search until we find something
	for i := 0; i < 5; i++ {
		// search binds
		for _, socketInfo := range binds {
			if localPort == socketInfo.Local.Port &&
				(socketInfo.Local.IP[0] == 0 || // zero IP
					isInboundMulticast || // inbound broadcast, multicast
					localIP.Equal(socketInfo.Local.IP)) {

				// do not check direction if remoteIP/Port is not given
				if pktInfo.RemotePort() == 0 {
					return checkBindPID(socketInfo, pktInfo.Inbound)
				}

				// get direction and return
				connInbound := getUDPDirection(socketInfo, udpStates, pktInfo)
				return checkBindPID(socketInfo, connInbound)
			}
		}

		// we found nothing, we could have been too fast, give the kernel some time to think
		// back off timer: with 3ms baseWaitTime: 3, 6, 9, 12, 15, 18, 21ms - 84ms in total
		time.Sleep(time.Duration(i+1) * baseWaitTime)

		// refetch lists
		binds = updateTable()
	}

	return socket.UnidentifiedProcessID, pktInfo.Inbound, ErrConnectionNotFound
}
