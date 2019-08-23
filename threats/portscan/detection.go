package portscan

import (
	"github.com/safing/portbase/log"
	"github.com/safing/portbase/modules"
	"github.com/safing/portmaster/firewall/inspection"
	"github.com/safing/portmaster/network"
	"github.com/safing/portmaster/network/netutils"
	"github.com/safing/portmaster/network/packet"
)

var (
	portscanInspectorIndex  int
	portscanDetectionModule = modules.Register("portscan", prep, nil, nil)
)

const ()

func prep() error {
	portscanInspectorIndex = inspection.RegisterInspector("portscanDetection", inspector, network.VerdictAccept)

	return nil
}

type Inspect struct {
}

func inspector(pkt packet.Packet, link *network.Link) uint8 {
	log.Tracer(pkt.Ctx()).Trace("entering portscan-inspacetion")

	// only check Ingoing
	if link.Communication().Direction == network.Outbound {
		log.Tracer(pkt.Ctx()).Trace("leaving portscan-inspacetion: network.Outbound")
		return inspection.STOP_INSPECTING
	}

	//TODO: Arp?

	// whitelist Multicast, Broadcast, Localhost
	switch netutils.ClassifyIP(pkt.Info().RemoteIP()) {
	case netutils.HostLocal, netutils.LocalMulticast, netutils.GlobalMulticast: // TODO: Broadcasts like 192.0.2.255/24
		log.Tracer(pkt.Ctx()).Trace("leaving portscan-inspacetion: netutils.HostLocal, netutils.LocalMulticast, netutils.GlobalMulticast")
		return inspection.STOP_INSPECTING
	}

	protocol := pkt.Info().Protocol
	port := pkt.Info().DstPort

	// whitelist ICMP, ICMPv6, IGMP, mDNS, NetBios
	switch protocol {
	case packet.ICMP, packet.ICMPv6, packet.IGMP:
		log.Tracer(pkt.Ctx()).Trace("leaving portscan-inspacetion: packet.ICMP, packet.ICMPv6, packet.IGMP")
		return inspection.STOP_INSPECTING
	case packet.UDP:
		switch port {
		case 5353, 137, 138: // mDNS, NetBios, NetBios
			log.Tracer(pkt.Ctx()).Trace("leaving portscan-inspacetion: packet.UDP && Port: 5353, 137, 138")
			return inspection.STOP_INSPECTING
		}
	case packet.TCP:
		if port == 139 { // NetBios
			log.Tracer(pkt.Ctx()).Trace("leaving portscan-inspacetion: packet.TCP && Port: 139")
			return inspection.STOP_INSPECTING
		}
	}

	log.Tracer(pkt.Ctx()).Trace("possible portscan-packet")

	// get or create link-specific inspection data
	/*	var inspect *Inspect
		inspectorData, ok := link.GetInspectorData()[uint8(portscanInspectorIndex)]
		if ok {
			inspect, ok = inspectorData.(*Inspect)
		}
		if !ok {
			inspect = new(Inspect)
			link.GetInspectorData()[uint8(portscanInspectorIndex)] = inspect

			// load config for link
			//inspect.SecurityLevel = link.Connection().Process().Profile.SecurityLevel

		}*/

	return inspection.DO_NOTHING
}

func processMessage(portscanInspection *Inspect, data []byte, pkt packet.Packet, link *network.Link) (action uint8) {

	return

}
