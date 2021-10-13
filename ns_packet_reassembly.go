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

	sg.Fetch(available)

	fmt.Printf("ReassembledSG (available: %v) (saved: %v) (dir: %v) (start :%v) (end :%v), (skip: %v)\n",
		available, saved, direction, start, end, skip)
}

func (s *nsStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	fmt.Printf("ReassemblyComplete\n")
	return true
}

func (a *nsAssemblerContext) GetCaptureInfo() gopacket.CaptureInfo {
	return a.ci
}

func internalStart(pid int, ifc string, pool *reassembly.StreamPool) error {
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

		context := &nsAssemblerContext{
			ci: p.Metadata().CaptureInfo,
		}

		assembler.AssembleWithContext(p.NetworkLayer().NetworkFlow(), tcp, context)
	}
}

func start(wg *sync.WaitGroup, pid int, ifc string, pool *reassembly.StreamPool) error {
	defer wg.Done()

	err := internalStart(pid, ifc, pool)

	switch err := err.(type) {
	case *errors.Error:
		fmt.Printf("Error: %v\n", err.ErrorStack())
	default:
		fmt.Printf("Error: %v\n", err)
	}

	return err
}

func runNsReassmble() error {
	factory := nsStreamFactory{}
	pool := reassembly.NewStreamPool(&factory)

	var wg sync.WaitGroup

	wg.Add(1)
	go start(&wg, 322295, "lo", pool)
	wg.Add(1)
	go start(&wg, 322323, "lo", pool)
	wg.Add(1)
	go start(&wg, 0, "lo", pool)

	wg.Wait()

	return nil
}
