package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"
	"xdpcap/internal/recorder"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package recorder -output-dir ../../internal/recorder pcap ../../bpf/pcap.c

func main() {
	flags, err := parseFlags(os.Args[0], os.Args[1:])
	switch {
	case err == flag.ErrHelp:
		fmt.Fprintln(os.Stdout, flags.Usage())
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "Error: %v\n\nUsage: %s", err, flags.Usage())
		os.Exit(1)
	}
	defer flags.writer.Close()

	if err := capture(flags); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(2)
	}
}

func capture(flags flags) error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	r, err := recorder.New(recorder.RecorderOption{
		Interface:     flags.iface,
		PerCPUBuffer:  flags.perCPUBuffer,
		PerfWatermark: flags.perfWatermark,
	})
	if err != nil {
		return err
	}
	defer r.Close()

	pcapWriter, err := createPcapWriter(flags.writer, flags.iface)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}
	defer pcapWriter.Flush()

	packets := 0
	for {
		select {
		case <-sig:
			fmt.Fprintf(os.Stdout, "Got %d packets\n", packets)
			return nil
		default:
			data, err := r.Read()
			switch {
			case err == recorder.ErrRecorderClosed:
				return nil
			case err != nil:
				fmt.Fprintln(os.Stderr, "Error: ", err)
				continue
			}

			ci := gopacket.CaptureInfo{
				Timestamp:      time.Now(),
				CaptureLength:  len(data),
				Length:         len(data),
				InterfaceIndex: 0,
			}

			if err := pcapWriter.WritePacket(ci, data); err != nil {
				fmt.Fprintln(os.Stderr, "Error writing packet: ", err)
			}
			packets++
			if flags.flush {
				if err := pcapWriter.Flush(); err != nil {
					fmt.Fprintln(os.Stderr, "Error flushing data: ", err)
				}
			}
		}
	}
}

func createPcapWriter(w io.Writer, iface net.Interface) (*pcapgo.NgWriter, error) {
	pcapWriter, err := pcapgo.NewNgWriterInterface(w, pcapgo.NgInterface{
		Name:       iface.Name,
		LinkType:   layers.LinkTypeEthernet,
		SnapLength: 0,
	}, pcapgo.NgWriterOptions{})
	return pcapWriter, errors.Wrap(err, "pcap writer")
}
