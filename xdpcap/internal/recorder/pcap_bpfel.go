// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package recorder

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadPcap returns the embedded CollectionSpec for pcap.
func loadPcap() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_PcapBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load pcap: %w", err)
	}

	return spec, err
}

// loadPcapObjects loads pcap and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*pcapObjects
//	*pcapPrograms
//	*pcapMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadPcapObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadPcap()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// pcapSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pcapSpecs struct {
	pcapProgramSpecs
	pcapMapSpecs
}

// pcapSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pcapProgramSpecs struct {
	CaptureProg *ebpf.ProgramSpec `ebpf:"capture_prog"`
}

// pcapMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pcapMapSpecs struct {
	PacketPerf *ebpf.MapSpec `ebpf:"packet_perf"`
}

// pcapObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadPcapObjects or ebpf.CollectionSpec.LoadAndAssign.
type pcapObjects struct {
	pcapPrograms
	pcapMaps
}

func (o *pcapObjects) Close() error {
	return _PcapClose(
		&o.pcapPrograms,
		&o.pcapMaps,
	)
}

// pcapMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadPcapObjects or ebpf.CollectionSpec.LoadAndAssign.
type pcapMaps struct {
	PacketPerf *ebpf.Map `ebpf:"packet_perf"`
}

func (m *pcapMaps) Close() error {
	return _PcapClose(
		m.PacketPerf,
	)
}

// pcapPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadPcapObjects or ebpf.CollectionSpec.LoadAndAssign.
type pcapPrograms struct {
	CaptureProg *ebpf.Program `ebpf:"capture_prog"`
}

func (p *pcapPrograms) Close() error {
	return _PcapClose(
		p.CaptureProg,
	)
}

func _PcapClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed pcap_bpfel.o
var _PcapBytes []byte
