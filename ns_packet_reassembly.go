package main

import (
	"fmt"
	"sync"

	"github.com/go-errors/errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/vishvananda/netns"
)

type packetInfo struct {
	packet gopacket.Packet
	pid    int
	ifc    string
}

type nsStreamFactory struct{}
type nsStream struct{}
type nsAssemblerContext struct {
	ci gopacket.CaptureInfo
}

func (s *nsStreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP,
	ac reassembly.AssemblerContext) reassembly.Stream {
	return &nsStream{}
}

func (s *nsStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection,
	nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	return true
}

func (s *nsStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	available, saved := sg.Lengths()
	direction, start, end, skip := sg.Info()

	packet := ac.GetCaptureInfo().AncillaryData[0].(packetInfo)

	fmt.Printf("ReassembledSG (available: %v) (saved: %v) (dir: %v) (start :%v) (end :%v), (skip: %v) (pid: %v) (ifc: %v)\n",
		available, saved, direction, start, end, skip, packet.pid, packet.ifc)
}

func (s *nsStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	fmt.Printf("ReassemblyComplete\n")
	return true
}

func (a *nsAssemblerContext) GetCaptureInfo() gopacket.CaptureInfo {
	return a.ci
}

func internalStart(pid int, ifc string, packets chan<- packetInfo) error {
	fmt.Printf("Listening to interface %v\n", ifc)

	if pid != 0 {
		nsh, err := netns.GetFromPath(fmt.Sprintf("/proc/%v/ns/net", pid))

		if err != nil {
			return err
		}

		if err := netns.Set(nsh); err != nil {
			return err
		}
	}

	fmt.Printf("Starting with pid %d, ifc: %v\n", pid, ifc)

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

		if err != nil {
			return errors.Wrap(err, 0)
		}

		p := gopacket.NewPacket(bytes, gopacket.DecodersByLayerName["Ethernet"], gopacket.DecodeOptions{})
		packets <- packetInfo{
			packet: p,
			pid:    pid,
			ifc:    ifc,
		}
	}
}

func start(wg *sync.WaitGroup, pid int, ifc string, packets chan<- packetInfo) error {
	defer wg.Done()

	err := internalStart(pid, ifc, packets)

	switch err := err.(type) {
	case *errors.Error:
		fmt.Printf("Error: %v\n", err.ErrorStack())
	default:
		fmt.Printf("Error: %v\n", err)
	}

	return err
}

func readPackets(assembler *reassembly.Assembler, packets <-chan packetInfo) {
	for {
		p, more := <-packets

		if !more {
			return
		}

		packet := p.packet

		tcplayer := packet.TransportLayer()
		tcp, ok := tcplayer.(*layers.TCP)

		if !ok {
			fmt.Printf("Non TCP packet, skipping\n")
			continue
		}
		context := &nsAssemblerContext{
			ci: packet.Metadata().CaptureInfo,
		}

		context.ci.AncillaryData = append(context.ci.AncillaryData, p)

		assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, context)
	}
}

func runNsReassmble() error {
	factory := nsStreamFactory{}
	pool := reassembly.NewStreamPool(&factory)
	assembler := reassembly.NewAssembler(pool)
	assembler.AssemblerOptions.MaxBufferedPagesTotal = 1000
	assembler.AssemblerOptions.MaxBufferedPagesPerConnection = 1000

	packets := make(chan packetInfo, 10000)

	fmt.Printf("Assembler %+v\n", assembler)

	var wg sync.WaitGroup

	wg.Add(1)
	go start(&wg, 50503, "lo", packets)
	wg.Add(1)
	go start(&wg, 50554, "lo", packets)
	wg.Add(1)
	go start(&wg, 0, "lo", packets)

	go readPackets(assembler, packets)
	wg.Wait()
	close(packets)

	return nil
}
