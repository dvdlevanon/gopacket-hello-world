package main

import (
	"fmt"
	"os"

	"github.com/go-errors/errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func runSniffer() error {
	ifc := "lo"

	if len(os.Args) > 2 {
		ifc = os.Args[2]
	}

	fmt.Printf("Listening to interface %v\n", ifc)

	inactive, err := pcap.NewInactiveHandle(ifc)

	if err != nil {
		return errors.Wrap(err, 0)
	}

	defer inactive.CleanUp()

	inactive.SetTimeout(pcap.BlockForever)

	fmt.Printf("Inactive %+v\n", inactive)
	handle, err := inactive.Activate()

	if err != nil {
		return errors.Wrap(err, 0)
	}

	fmt.Printf("Handle %+v\n", handle)
	defer handle.Close()

	for {
		bytes, _, err := handle.ReadPacketData()

		p := gopacket.NewPacket(bytes, gopacket.DecodersByLayerName["Ethernet"], gopacket.DecodeOptions{})

		if err != nil {
			return errors.Wrap(err, 0)
		}

		tcplayer := p.TransportLayer()
		tcp := tcplayer.(*layers.TCP)

		fmt.Printf("%v:%v -> %v:%v - (syn: %v) (ack: %v) (fin: %v) - (seq: %v) (ack: %v) (win: %v)\n",
			p.NetworkLayer().NetworkFlow().Src(), p.TransportLayer().TransportFlow().Src(),
			p.NetworkLayer().NetworkFlow().Dst(), p.TransportLayer().TransportFlow().Dst(),
			tcp.SYN, tcp.ACK, tcp.FIN,
			tcp.Seq, tcp.Ack, tcp.Window)
	}
}
