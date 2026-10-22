package capture

import "fmt"

// Channel describes one wireless channel.
type Channel struct {
	Number int
	Freq   uint32 // centre frequency in MHz
	Band   string
}

// String renders the channel.
func (c Channel) String() string {
	return fmt.Sprintf("channel %d (%d MHz, %s GHz band)", c.Number, c.Freq, c.Band)
}

// Band returns the band a channel belongs to.
//
// The channel numbers of the 2.4 GHz, the 5 GHz and the 6 GHz band overlap,
// so the bands are told apart by the ranges that do not collide: 1 to 14 are
// in the 2.4 GHz band, 36 to 177 in the 5 GHz band and 178 to 233 in the
// 6 GHz band.
func Band(number int) string {
	switch {
	case number >= 1 && number <= 14:
		return "2.4"
	case number >= 36 && number <= 177:
		return "5"
	case number >= 178 && number <= 233:
		return "6"
	}
	return "unknown"
}

// ChannelFreq returns the centre frequency of a channel in MHz.
//
// The 2.4 GHz band uses the classic formula 2407 + 5*n with the exception of
// channel 14, and the 5 GHz and 6 GHz bands are laid out as in the IEEE 802.11
// amendment that introduced them.  The 6 GHz band is only resolved for the
// channels that do not collide with the other two bands, because the 6 GHz
// band reuses the channel numbers of the 5 GHz band.
func ChannelFreq(number int) (uint32, bool) {
	switch {
	case number >= 1 && number <= 13:
		return uint32(2407 + 5*number), true
	case number == 14:
		return 2484, true
	case number >= 36 && number <= 177:
		// The 5 GHz band is 5000 + 5*n for the channels that are in use.
		switch {
		case number%4 == 0 && number <= 64:
			return uint32(5000 + 5*number), true
		case number >= 100 && number <= 144 && number%4 == 0:
			return uint32(5000 + 5*number), true
		case number >= 149 && number <= 177 && number%4 == 1:
			return uint32(5000 + 5*number), true
		}
		return 0, false
	case number >= 178 && number <= 233 && number%4 == 1:
		// The 6 GHz band starts at channel 1 with a centre of 5955 MHz.
		return uint32(5955 + 5*(number-1)), true
	}
	return 0, false
}

// Channels returns the channels the auditor scans by default.
func Channels() []Channel {
	var out []Channel
	for n := 1; n <= 13; n++ {
		f, _ := ChannelFreq(n)
		out = append(out, Channel{Number: n, Freq: f, Band: Band(n)})
	}
	for _, n := range []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
		116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165} {
		f, ok := ChannelFreq(n)
		if !ok {
			continue
		}
		out = append(out, Channel{Number: n, Freq: f, Band: Band(n)})
	}
	return out
}

// ChannelByNumber looks a channel up in the list.
func ChannelByNumber(number int) (Channel, bool) {
	for _, c := range Channels() {
		if c.Number == number {
			return c, true
		}
	}
	f, ok := ChannelFreq(number)
	if !ok {
		return Channel{}, false
	}
	return Channel{Number: number, Freq: f, Band: Band(number)}, true
}
