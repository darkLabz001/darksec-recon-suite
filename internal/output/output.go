// Package output renders scan results in a variety of machine and human
// readable formats.
package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/darkLabz001/darksec-recon-suite/vantage/internal/engine"
)

// Format identifies an output rendering.
type Format string

const (
	// FormatText renders an aligned human readable table.
	FormatText Format = "text"
	// FormatJSON renders a single JSON document.
	FormatJSON Format = "json"
	// FormatJSONL renders one JSON document per line.
	FormatJSONL Format = "jsonl"
	// FormatCSV renders comma separated values.
	FormatCSV Format = "csv"
	// FormatGreppable renders "ip:port service version" lines.
	FormatGreppable Format = "greppable"
	// FormatTemplate renders a user supplied Go template.
	FormatTemplate Format = "template"
)

// Options configures a writer.
type Options struct {
	// Format selects the rendering.
	Format Format
	// Output is the destination stream.
	Output io.Writer
	// Template is the Go template used by FormatTemplate.
	Template string
	// NoColor disables ANSI colouring of the text format.
	NoColor bool
	// ShowAll includes closed and filtered ports in the text output.
	ShowAll bool
}

// Writer renders results.
type Writer struct {
	opts    Options
	tmpl    *template.Template
	csvw    *csv.Writer
	started time.Time

	// jsonStarted records whether the JSON document has been opened.
	jsonStarted bool
}

// jsonResult is the JSON representation of a scan result.
type jsonResult struct {
	IP         string    `json:"ip"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	State      string    `json:"state"`
	Service    string    `json:"service,omitempty"`
	Product    string    `json:"product,omitempty"`
	Version    string    `json:"version,omitempty"`
	Extra      string    `json:"extra,omitempty"`
	CPE        string    `json:"cpe,omitempty"`
	Banner     string    `json:"banner,omitempty"`
	Confidence float64   `json:"confidence,omitempty"`
	Method     string    `json:"method,omitempty"`
	RTTMs      float64   `json:"rtt_ms"`
	JA3        string    `json:"ja3,omitempty"`
	JA3S       string    `json:"ja3s,omitempty"`
	Favicon    string    `json:"favicon,omitempty"`
	TLS        *tlsInfo  `json:"tls,omitempty"`
	HTTP       *httpInfo `json:"http,omitempty"`
}

type tlsInfo struct {
	Version     string   `json:"version,omitempty"`
	CipherSuite string   `json:"cipher_suite,omitempty"`
	ALPN        string   `json:"alpn,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Serial      string   `json:"serial,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	Expired     bool     `json:"expired,omitempty"`
	SelfSigned  bool     `json:"self_signed,omitempty"`
	SANs        []string `json:"sans,omitempty"`
	KeyType     string   `json:"key_type,omitempty"`
	SigAlg      string   `json:"signature_algorithm,omitempty"`
}

type httpInfo struct {
	Status      int               `json:"status,omitempty"`
	StatusText  string            `json:"status_text,omitempty"`
	HTTPVersion string            `json:"http_version,omitempty"`
	Title       string            `json:"title,omitempty"`
	Server      string            `json:"server,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Redirect    string            `json:"redirect,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyBytes   int               `json:"body_bytes,omitempty"`
}

// New returns a writer ready for use.
func New(opts Options) (*Writer, error) {
	if opts.Output == nil {
		opts.Output = io.Discard
	}
	w := &Writer{opts: opts, started: time.Now()}

	switch opts.Format {
	case FormatTemplate:
		if opts.Template == "" {
			return nil, fmt.Errorf("template format requires a template")
		}
		tmpl, err := template.New("vantage").Funcs(templateFuncs()).Parse(opts.Template)
		if err != nil {
			return nil, fmt.Errorf("invalid template: %w", err)
		}
		w.tmpl = tmpl
	case FormatCSV:
		w.csvw = csv.NewWriter(opts.Output)
		if err := w.csvw.Write(csvHeader()); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func csvHeader() []string {
	return []string{"ip", "port", "protocol", "state", "service", "product", "version", "cpe", "rtt_ms"}
}

// Write renders a single result.
func (w *Writer) Write(res engine.Result) error {
	switch w.opts.Format {
	case FormatJSON:
		return w.writeJSON(res)
	case FormatJSONL:
		enc := json.NewEncoder(w.opts.Output)
		return enc.Encode(toJSON(res))
	case FormatCSV:
		return w.csvw.Write(csvRow(res))
	case FormatGreppable:
		return w.writeGreppable(res)
	case FormatTemplate:
		return w.tmpl.Execute(w.opts.Output, templateDataOf(res))
	default:
		return w.writeText(res)
	}
}

// writeJSON streams a single result into a JSON array.
//
// The array is written incrementally so that a large scan does not have
// to hold every result in memory.
func (w *Writer) writeJSON(res engine.Result) error {
	if !w.jsonStarted {
		w.jsonStarted = true
		if _, err := io.WriteString(w.opts.Output, "[\n"); err != nil {
			return err
		}
	} else {
		if _, err := io.WriteString(w.opts.Output, ",\n"); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(toJSON(res), "", "  ")
	if err != nil {
		return err
	}
	// Indent the object by one level so that it sits inside the array.
	var buf bytes.Buffer
	for i, line := range bytes.Split(data, []byte("\n")) {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString("  ")
		buf.Write(line)
	}
	_, err = w.opts.Output.Write(buf.Bytes())
	return err
}

// Close flushes any buffered output.
func (w *Writer) Close() error {
	switch w.opts.Format {
	case FormatJSON:
		if !w.jsonStarted {
			_, err := io.WriteString(w.opts.Output, "[]\n")
			return err
		}
		_, err := io.WriteString(w.opts.Output, "\n]\n")
		return err
	case FormatCSV:
		w.csvw.Flush()
		return w.csvw.Error()
	}
	return nil
}

// writeText renders the human readable table.
func (w *Writer) writeText(res engine.Result) error {
	if !w.opts.ShowAll && res.State != engine.StateOpen {
		return nil
	}

	color := !w.opts.NoColor
	state := string(res.State)
	switch res.State {
	case engine.StateOpen:
		if color {
			state = "\x1b[32mopen\x1b[0m"
		}
	case engine.StateClosed:
		if color {
			state = "\x1b[31mclosed\x1b[0m"
		}
	default:
		if color {
			state = "\x1b[33mfiltered\x1b[0m"
		}
	}

	service, product, version := serviceColumns(res)
	endpoint := res.Endpoint()
	rtt := fmt.Sprintf("%.2fms", float64(res.RTT.Microseconds())/1000)

	fields := []string{
		pad(endpoint, 26),
		pad(state, 16),
		pad(service, 12),
		pad(product, 18),
		pad(version, 14),
		rtt,
	}
	line := strings.Join(fields, " ")
	if extra := extraColumn(res); extra != "" {
		line += " " + extra
	}
	_, err := fmt.Fprintln(w.opts.Output, line)
	return err
}

// writeGreppable renders the compact "ip:port service version" form.
func (w *Writer) writeGreppable(res engine.Result) error {
	if res.State != engine.StateOpen {
		return nil
	}
	service, product, version := serviceColumns(res)
	parts := []string{res.Endpoint()}
	if service != "" {
		parts = append(parts, service)
	}
	if product != "" {
		parts = append(parts, product)
	}
	if version != "" {
		parts = append(parts, version)
	}
	_, err := fmt.Fprintln(w.opts.Output, strings.Join(parts, " "))
	return err
}

func serviceColumns(res engine.Result) (service, product, version string) {
	if res.Service == nil {
		return "", "", ""
	}
	return res.Service.Service, res.Service.Product, res.Service.Version
}

func extraColumn(res engine.Result) string {
	if res.Service == nil {
		return ""
	}
	var parts []string
	if res.Service.Extra != "" {
		parts = append(parts, res.Service.Extra)
	}
	if res.Service.CPE != "" {
		parts = append(parts, res.Service.CPE)
	}
	return strings.Join(parts, " ")
}

func csvRow(res engine.Result) []string {
	service, product, version := serviceColumns(res)
	cpe := ""
	if res.Service != nil {
		cpe = res.Service.CPE
	}
	return []string{
		res.Addr.String(),
		strconv.Itoa(int(res.Port)),
		string(res.Proto),
		string(res.State),
		service,
		product,
		version,
		cpe,
		fmt.Sprintf("%.3f", float64(res.RTT.Microseconds())/1000),
	}
}

func toJSON(res engine.Result) jsonResult {
	out := jsonResult{
		IP:       res.Addr.String(),
		Port:     int(res.Port),
		Protocol: string(res.Proto),
		State:    string(res.State),
		RTTMs:    float64(res.RTT.Microseconds()) / 1000,
	}
	if res.Service == nil {
		return out
	}
	out.Service = res.Service.Service
	out.Product = res.Service.Product
	out.Version = res.Service.Version
	out.Extra = res.Service.Extra
	out.CPE = res.Service.CPE
	out.Banner = res.Service.Banner
	out.Confidence = res.Service.Confidence
	out.Method = res.Service.Method
	out.JA3 = res.Service.JA3
	out.JA3S = res.Service.JA3S
	out.Favicon = res.Service.Favicon

	if res.Service.TLS != nil {
		out.TLS = &tlsInfo{
			Version:     res.Service.TLS.Version,
			CipherSuite: res.Service.TLS.CipherSuite,
			ALPN:        res.Service.TLS.ALPN,
			Subject:     res.Service.TLS.Subject,
			Issuer:      res.Service.TLS.Issuer,
			Serial:      res.Service.TLS.Serial,
			NotBefore:   res.Service.TLS.NotBefore,
			NotAfter:    res.Service.TLS.NotAfter,
			Expired:     res.Service.TLS.Expired,
			SelfSigned:  res.Service.TLS.SelfSigned,
			SANs:        res.Service.TLS.SANs,
			KeyType:     res.Service.TLS.KeyType,
			SigAlg:      res.Service.TLS.SigAlg,
		}
	}
	if res.Service.HTTP != nil {
		out.HTTP = &httpInfo{
			Status:      res.Service.HTTP.Status,
			StatusText:  res.Service.HTTP.StatusText,
			HTTPVersion: res.Service.HTTP.HTTPVersion,
			Title:       res.Service.HTTP.Title,
			Server:      res.Service.HTTP.Server,
			ContentType: res.Service.HTTP.ContentType,
			Redirect:    res.Service.HTTP.Redirect,
			Headers:     res.Service.HTTP.Headers,
			BodyBytes:   res.Service.HTTP.BodyBytes,
		}
	}
	return out
}

// templateData is the value exposed to user supplied templates.
type templateData struct {
	IP         string
	Port       int
	Endpoint   string
	Protocol   string
	State      string
	Service    string
	Product    string
	Version    string
	Extra      string
	CPE        string
	Banner     string
	Confidence float64
	Method     string
	RTTMs      float64
	JA3        string
	JA3S       string
	Favicon    string
	Title      string
	Server     string
	Status     int
}

func templateDataOf(res engine.Result) templateData {
	data := templateData{
		IP:       res.Addr.String(),
		Port:     int(res.Port),
		Endpoint: res.Endpoint(),
		Protocol: string(res.Proto),
		State:    string(res.State),
		RTTMs:    float64(res.RTT.Microseconds()) / 1000,
	}
	if res.Service == nil {
		return data
	}
	data.Service = res.Service.Service
	data.Product = res.Service.Product
	data.Version = res.Service.Version
	data.Extra = res.Service.Extra
	data.CPE = res.Service.CPE
	data.Banner = res.Service.Banner
	data.Confidence = res.Service.Confidence
	data.Method = res.Service.Method
	data.JA3 = res.Service.JA3
	data.JA3S = res.Service.JA3S
	data.Favicon = res.Service.Favicon
	if res.Service.HTTP != nil {
		data.Title = res.Service.HTTP.Title
		data.Server = res.Service.HTTP.Server
		data.Status = res.Service.HTTP.Status
	}
	return data
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"trim":  strings.TrimSpace,
		"join":  strings.Join,
	}
}

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
