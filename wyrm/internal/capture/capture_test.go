package capture

import "testing"

func TestChannelFreq(t *testing.T) {
	cases := []struct {
		number int
		freq   uint32
	}{
		{1, 2412},
		{6, 2437},
		{11, 2462},
		{13, 2472},
		{14, 2484},
		{36, 5180},
		{40, 5200},
		{48, 5240},
		{100, 5500},
		{144, 5720},
		{149, 5745},
		{157, 5785},
		{165, 5825},
	}
	for _, c := range cases {
		got, ok := ChannelFreq(c.number)
		if !ok {
			t.Errorf("the channel %d is not known", c.number)
			continue
		}
		if got != c.freq {
			t.Errorf("the channel %d reads %d MHz, want %d", c.number, got, c.freq)
		}
	}
}

func TestChannelFreqRejectsUnknownChannels(t *testing.T) {
	for _, number := range []int{0, -1, 15, 35, 99, 178, 234, 1000} {
		if _, ok := ChannelFreq(number); ok {
			t.Errorf("the channel %d must not be resolved", number)
		}
	}
}

func TestChannelFreqOfTheSixGigahertzBand(t *testing.T) {
	// The 6 GHz band reuses the channel numbers of the 5 GHz band, so
	// only the channels that do not collide are resolved.
	freq, ok := ChannelFreq(181)
	if !ok {
		t.Fatal("the channel 181 is not known")
	}
	if freq != 6855 {
		t.Errorf("the channel 181 reads %d MHz, want 6855", freq)
	}

	// The channel 37 is a channel of the 5 GHz band that is not in use,
	// and the 6 GHz band reuses the numbers of the 5 GHz band, so it is
	// not resolved either.
	if _, ok := ChannelFreq(37); ok {
		t.Error("the channel 37 must not be resolved")
	}
}

func TestBand(t *testing.T) {
	cases := map[int]string{
		1:    "2.4",
		6:    "2.4",
		14:   "2.4",
		36:   "5",
		149:  "5",
		165:  "5",
		181:  "6",
		0:    "unknown",
		9999: "unknown",
	}
	for number, want := range cases {
		if got := Band(number); got != want {
			t.Errorf("the channel %d reads the band %q, want %q", number, got, want)
		}
	}
}

func TestChannels(t *testing.T) {
	list := Channels()
	if len(list) == 0 {
		t.Fatal("the list of channels is empty")
	}

	seen := map[int]bool{}
	for _, c := range list {
		if seen[c.Number] {
			t.Errorf("the channel %d is listed twice", c.Number)
		}
		seen[c.Number] = true
		if c.Freq == 0 {
			t.Errorf("the channel %d has no frequency", c.Number)
		}
		if c.Band == "unknown" {
			t.Errorf("the channel %d has no band", c.Number)
		}
		if c.Number < 1 || c.Number > 14 {
			if c.Band == "2.4" {
				t.Errorf("the channel %d is in the 2.4 GHz band", c.Number)
			}
		}
	}

	// The list has to hold the classic 2.4 GHz channels and the 5 GHz
	// channels that are in use.
	for _, number := range []int{1, 6, 11, 13, 36, 40, 48, 149, 165} {
		if !seen[number] {
			t.Errorf("the channel %d is missing from the list", number)
		}
	}
}

func TestChannelByNumber(t *testing.T) {
	c, ok := ChannelByNumber(6)
	if !ok {
		t.Fatal("the channel 6 is not known")
	}
	if c.Number != 6 || c.Freq != 2437 || c.Band != "2.4" {
		t.Errorf("the channel 6 reads %+v", c)
	}

	c, ok = ChannelByNumber(149)
	if !ok {
		t.Fatal("the channel 149 is not known")
	}
	if c.Freq != 5745 || c.Band != "5" {
		t.Errorf("the channel 149 reads %+v", c)
	}

	// A channel that is not in the default list but that has a frequency
	// is still resolved.
	c, ok = ChannelByNumber(11)
	if !ok || c.Number != 11 {
		t.Errorf("the channel 11 reads %+v, %v", c, ok)
	}

	if _, ok := ChannelByNumber(0); ok {
		t.Error("the channel 0 must not be resolved")
	}
	if _, ok := ChannelByNumber(38); ok {
		t.Error("the channel 38 must not be resolved")
	}
}

func TestChannelString(t *testing.T) {
	c := Channel{Number: 6, Freq: 2437, Band: "2.4"}
	if got := c.String(); got != "channel 6 (2437 MHz, 2.4 GHz band)" {
		t.Errorf("the channel reads %q", got)
	}
}

func TestTcpdumpCommand(t *testing.T) {
	c := &Capture{opts: Options{
		Interface:   "wlp4s0",
		SnapshotLen: 0,
		Filter:      "type mgt",
	}}
	args := c.tcpdumpCommand()
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	want := "-i wlp4s0 -s 0 -U -n -w - type mgt "
	if joined != want {
		t.Errorf("the command reads %q, want %q", joined, want)
	}
}

func TestTcpdumpCommandWithoutAFilter(t *testing.T) {
	c := &Capture{opts: Options{Interface: "wlp4s0"}}
	args := c.tcpdumpCommand()
	for _, a := range args {
		if a == "type" {
			t.Error("the command must not carry a filter")
		}
	}
}
