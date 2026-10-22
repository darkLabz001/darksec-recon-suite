package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/wyrm/internal/pcap"
)

// Options configures a live capture.
type Options struct {
	// Interface is the wireless interface to capture on.
	Interface string
	// Channels is the list of channels to hop over.  A single entry means
	// the radio stays on that channel.
	Channels []int
	// Hop asks the radio to walk the channel list.  It has no effect when
	// only one channel was given.
	Hop bool
	// HopInterval is how long the radio stays on each channel.
	HopInterval time.Duration
	// Monitor asks for the interface to be switched to monitor mode.  That
	// takes the interface off the network, so the caller has to confirm it.
	Monitor bool
	// Filter is a tcpdump filter expression.
	Filter string
	// Output is the file the capture is written to.  An empty name keeps
	// the capture in memory only.
	Output string
	// SnapshotLen is the number of bytes captured per frame.  Zero means
	// the whole frame.
	SnapshotLen int
	// SudoPassword is used when the tool is not running as root and the
	// capture has to be started through sudo.
	SudoPassword string
	// Logger receives progress messages.
	Logger func(format string, args ...any)
}

// Capture is a prepared live capture.
type Capture struct {
	opts     Options
	radio    *Radio
	iface    *Interface
	restored bool
	out      *os.File
	tee      *os.File
}

// Prepare puts the radio into the state the capture needs.  When the capture
// ends the radio is returned to the state it was in before.
func Prepare(opts Options) (*Capture, error) {
	if opts.Interface == "" {
		return nil, errors.New("capture: no interface was given")
	}
	if opts.Logger == nil {
		opts.Logger = func(string, ...any) {}
	}
	if opts.SnapshotLen == 0 {
		opts.SnapshotLen = 0
	}
	c := &Capture{opts: opts}

	if opts.Monitor || len(opts.Channels) > 0 {
		radio, err := OpenRadio()
		if err != nil {
			return nil, err
		}
		c.radio = radio
		iface, err := radio.QueryInterface(opts.Interface)
		if err != nil {
			radio.Close()
			return nil, err
		}
		c.iface = iface
		if opts.Monitor && !iface.Monitor {
			opts.Logger("switching %s to monitor mode", opts.Interface)
			if err := radio.SetMonitor(iface.Index); err != nil {
				radio.Close()
				return nil, err
			}
			c.restored = true
		}
		if len(opts.Channels) > 0 {
			ch, ok := ChannelByNumber(opts.Channels[0])
			if !ok {
				radio.Close()
				return nil, fmt.Errorf("capture: %d is not a channel the tool knows", opts.Channels[0])
			}
			if err := radio.SetChannel(iface.Wiphy, ch.Freq, nlChanHT20); err != nil {
				radio.Close()
				return nil, err
			}
			opts.Logger("tuned %s to %s", opts.Interface, ch)
		}
	}

	if opts.Output != "" {
		f, err := os.Create(opts.Output)
		if err != nil {
			c.closeRadio()
			return nil, fmt.Errorf("capture: cannot create %s: %w", opts.Output, err)
		}
		c.out = f
	}
	return c, nil
}

// Radio exposes the radio control of the capture.
func (c *Capture) Radio() *Radio { return c.radio }

// Interface returns the nl80211 description of the captured interface.
func (c *Capture) Interface() *Interface { return c.iface }

// tcpdumpCommand builds the command line of the capture process.
func (c *Capture) tcpdumpCommand() []string {
	args := []string{
		"-i", c.opts.Interface,
		"-s", fmt.Sprintf("%d", c.opts.SnapshotLen),
		"-U",
		"-n",
		"-w", "-",
	}
	if c.opts.Filter != "" {
		args = append(args, c.opts.Filter)
	}
	return args
}

// Run performs the capture and hands every packet to handler.
func (c *Capture) Run(ctx context.Context, handler func(*pcap.Packet)) error {
	if c.opts.Output == "" && handler == nil {
		return errors.New("capture: a capture needs somewhere to put the packets")
	}
	if c.opts.Interface == "" {
		return errors.New("capture: no interface was given")
	}

	bin, err := exec.LookPath("tcpdump")
	if err != nil {
		return fmt.Errorf("capture: tcpdump is not installed: %w", err)
	}

	var cmd *exec.Cmd
	if IsRoot() {
		cmd = exec.Command(bin, c.tcpdumpCommand()...)
	} else {
		// A raw capture needs privileges.  The auditor never runs the
		// capture in a privileged helper of its own, so the password is
		// handed to sudo on the standard input.
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			return fmt.Errorf("capture: %s", "capturing needs root privileges or a password for sudo")
		}
		cmd = exec.Command(sudo, append([]string{"-S", "-p", "", "--", bin}, c.tcpdumpCommand()...)...)
		cmd.Stdin = strings.NewReader(c.opts.SudoPassword + "\n")
	}

	var stderr strings.Builder
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("capture: cannot open the capture pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("capture: cannot start tcpdump: %w", err)
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
		case <-stop:
		}
	}()

	if c.opts.Hop && len(c.opts.Channels) > 1 && c.opts.HopInterval > 0 {
		go c.hop(stop)
	}

	var src io.Reader = stdout
	if c.out != nil {
		c.tee = c.out
		src = io.TeeReader(stdout, c.out)
	}

	reader, err := pcap.NewReader(src)
	if err != nil {
		cmd.Process.Kill()
		return fmt.Errorf("capture: the capture stream is not a pcap stream: %w", err)
	}

	for {
		pkt, err := reader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if ctx.Err() != nil {
				break
			}
			cmd.Process.Kill()
			return fmt.Errorf("capture: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		if handler != nil {
			handler(pkt)
		}
	}

	waitErr := cmd.Wait()
	if ctx.Err() == nil && waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("capture: tcpdump failed: %s", msg)
		}
		return fmt.Errorf("capture: tcpdump failed: %w", waitErr)
	}
	return nil
}

// hop walks the channel list.
func (c *Capture) hop(stop <-chan struct{}) {
	if c.radio == nil || c.iface == nil {
		return
	}
	ticker := time.NewTicker(c.opts.HopInterval)
	defer ticker.Stop()
	i := 0
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			i = (i + 1) % len(c.opts.Channels)
			ch, ok := ChannelByNumber(c.opts.Channels[i])
			if !ok {
				continue
			}
			if err := c.radio.SetChannel(c.iface.Wiphy, ch.Freq, nlChanHT20); err != nil {
				c.opts.Logger("channel hop failed: %v", err)
				return
			}
			c.opts.Logger("hopped to %s", ch)
		}
	}
}

// Close stops the capture and returns the radio to its previous state.
func (c *Capture) Close() error {
	if c.out != nil {
		c.out.Close()
		c.out = nil
	}
	return c.closeRadio()
}

func (c *Capture) closeRadio() error {
	if c.radio == nil {
		return nil
	}
	if c.restored && c.iface != nil {
		_ = c.radio.SetManaged(c.iface.Index)
	}
	err := c.radio.Close()
	c.radio = nil
	return err
}

// Interfaces lists the wireless interfaces of the host.
func Interfaces() ([]string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, fmt.Errorf("capture: cannot list the network interfaces: %w", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if _, err := os.Stat("/sys/class/net/" + name + "/phy80211"); err == nil {
			out = append(out, name)
		}
	}
	return out, nil
}
