package main

import (
	"fmt"
	"os"

	"github.com/go-errors/errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

type streamFactory struct{}
type stream struct{}
type assemblerContext struct {
	ci gopacket.CaptureInfo
}

func (s *streamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP,
	ac reassembly.AssemblerContext) reassembly.Stream {
	return &stream{}
}

func (s *stream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func (s *stream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	available, saved := sg.Lengths()
	direction, start, end, skip := sg.Info()

	sg.Fetch(available)

	fmt.Printf("ReassembledSG (available: %v) (saved: %v) (dir: %v) (start :%v) (end :%v), (skip: %v)\n",
		available, saved, direction, start, end, skip)
}

func (s *stream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	fmt.Printf("ReassemblyComplete\n")
	return true
}

func (a *assemblerContext) GetCaptureInfo() gopacket.CaptureInfo {
	return a.ci
}

func runReassmble() error {
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

	factory := streamFactory{}
	pool := reassembly.NewStreamPool(&factory)
	assembler := reassembly.NewAssembler(pool)

	fmt.Printf("Assembler %+v\n", assembler)

	for {
		bytes, _, err := handle.ReadPacketData()

		p := gopacket.NewPacket(bytes, gopacket.DecodersByLayerName["Ethernet"], gopacket.DecodeOptions{})

		if err != nil {
			return errors.Wrap(err, 0)
		}

		tcplayer := p.TransportLayer()
		tcp := tcplayer.(*layers.TCP)

		context := &assemblerContext{
			ci: p.Metadata().CaptureInfo,
		}

		assembler.AssembleWithContext(p.NetworkLayer().NetworkFlow(), tcp, context)
	}
}
