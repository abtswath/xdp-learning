package recorder

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/pkg/errors"
)

type RecorderOption struct {
	Interface     net.Interface
	PerCPUBuffer  int
	PerfWatermark int
}

type Recorder struct {
	reader *perf.Reader
	objs   pcapObjects
	link   link.Link
}

func New(opts RecorderOption) (*Recorder, error) {
	var objs pcapObjects
	if err := loadPcapObjects(&objs, nil); err != nil {
		return nil, errors.Wrap(err, "load xdpcap objects")
	}

	reader, err := perf.NewReaderWithOptions(objs.PacketPerf, opts.PerCPUBuffer, perf.ReaderOptions{
		Watermark: opts.PerfWatermark,
	})
	if err != nil {
		objs.Close()
		return nil, errors.Wrap(err, "create perf reader")
	}
	recorder := &Recorder{
		reader: reader,
		objs:   objs,
	}
	err = recorder.attach(opts.Interface)
	if err != nil {
		recorder.Close()
	}

	return recorder, err
}

var ErrRecorderClosed = errors.New("recorder closed")

func (r *Recorder) attach(iface net.Interface) error {
	var err error
	r.link, err = link.AttachXDP(link.XDPOptions{
		Program:   r.objs.CaptureProg,
		Interface: iface.Index,
	})
	return err
}

func (r *Recorder) Read() ([]byte, error) {
	record, err := r.reader.Read()
	switch {
	case errors.Is(err, perf.ErrClosed):
		return nil, ErrRecorderClosed
	case err != nil:
		return nil, err
	}

	if record.LostSamples > 0 {
		return nil, errors.New("perf packet truncated")
	}

	raw := record.RawSample
	if len(raw) < 2 {
		return nil, errors.New("invalid packet")
	}
	length := int(binary.NativeEndian.Uint16(raw[:2]))
	data := raw[2:]
	if len(data) < length {
		return nil, errors.New("perf packet truncated")
	}

	return data[:length], nil
}

func (r *Recorder) Close() error {
	_ = r.reader.Close()
	_ = r.link.Close()
	return r.objs.Close()
}
