package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type flags struct {
	*flag.FlagSet
	writer        *os.File
	perCPUBuffer  int
	perfWatermark int
	iface         net.Interface
	flush         bool
}

func parseFlags(name string, args []string) (flags, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	flags := flags{
		FlagSet: fs,
	}

	flags.IntVar(&flags.perCPUBuffer, "buffer", 8192, "Per CPU perf buffer size (`bytes`)")
	flags.IntVar(&flags.perfWatermark, "watermark", 1, "Perf watermark (`bytes`), it must be less than buffer")
	flags.BoolVar(&flags.flush, "flush", false, "Flush output")

	var output string
	flags.StringVar(&output, "output", "", "Pcap output path, default is stdout")

	if err := flags.Parse(args); err != nil {
		return flags, err
	}
	if flags.NArg() < 1 {
		return flags, errors.New("missing required <interface>")
	}
	iface, err := net.InterfaceByName(flags.Arg(0))
	if err != nil {
		return flags, err
	}
	flags.iface = *iface

	if output == "" {
		flags.writer = os.Stdout
	} else {
		var err error
		flags.writer, err = os.Create(output)
		if err != nil {
			return flags, errors.Wrap(err, "creating output file")
		}
	}
	return flags, nil
}

func (f flags) Usage() string {

	usage := strings.Builder{}

	usage.WriteString(fmt.Sprintf(`%s [options] <interface>

`, f.Name()))

	f.SetOutput(&usage)
	f.PrintDefaults()
	f.SetOutput(io.Discard)
	return usage.String()
}
