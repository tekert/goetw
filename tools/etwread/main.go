package main

import (
	"context"
	"encoding/hex"
	"sort"
	"strconv"
	"unsafe"

	//"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/goccy/go-json"
	"github.com/tekert/goetw/etw"
)

// TODO: Permissions for some providers
// Consume from already created session, like attach.

// --- Custom Flag Types ---

// providerList is a custom flag type to allow specifying -p multiple times.
type providerList []string

func (p *providerList) String() string {
	return strings.Join(*p, ", ")
}

func (p *providerList) Set(value string) error {
	*p = append(*p, value)
	return nil
}

// idList is a custom flag type for comma-separated lists of uint16.
type idList []uint16

func (i *idList) String() string {
	if i == nil || len(*i) == 0 {
		return ""
	}
	s := make([]string, len(*i))
	for j, v := range *i {
		s[j] = strconv.Itoa(int(v))
	}
	return strings.Join(s, ",")
}

func (i *idList) Set(value string) error {
	if value == "" {
		*i = nil
		return nil
	}
	parts := strings.Split(value, ",")
	ids := make([]uint16, 0, len(parts))
	for _, part := range parts {
		val, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err != nil {
			return fmt.Errorf("invalid ID '%s': %w", part, err)
		}
		ids = append(ids, uint16(val))
	}
	*i = ids
	return nil
}

// --- Main Application Logic ---

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// TODO: better do -filter-id  flag that takes comma-separated list of IDs

func run() error {
	// 1. Flag Definitions
	var (
		providers       providerList
		kernelEventIDs  idList
		etlFile         string
		kernelProviders string
		sessionName     string
		debugLevel      string
		help            bool
	)

	flag.Var(&providers, "p", "Provider to trace in format:"+
		"\"(Name|GUID)[:Level[:EventIDs[:MatchAnyKeyword[:MatchAllKeyword]]]]\". Can be specified multiple times.")
	flag.StringVar(&etlFile, "etl", "", "Path to an .etl file to read.")
	flag.StringVar(&kernelProviders, "kernel", "", "Trace NT Kernel Logger providers. Provide a comma-separated list of keywords"+
		"(e.g., 'Process,Thread,DiskIo'). Use 'All' for a comprehensive set.")
	flag.Var(&kernelEventIDs, "kernel-ids", "Comma-separated list of Event IDs to include for kernel traces (e.g., '1,2,10').")
	flag.StringVar(&sessionName, "name", "etwread-tool", "Name for the real-time ETW session.")
	flag.StringVar(&debugLevel, "debug", "", "Set debug output level ('lite' or 'full').")
	flag.BoolVar(&help, "help", false, "Show this help message.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "A simple command-line tool to read and print ETW events.")
		fmt.Fprintln(os.Stderr, "You must specify one of three modes: -p (for specific providers), -kernel (for the NT Kernel Logger), or -etl (for a file).")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()

		fmt.Fprintln(os.Stderr, "\nKernel Provider Keywords:")
		fmt.Fprintln(os.Stderr, "  Use 'logman query providers \"Windows Kernel Trace\"' to see all keywords on your system.")
		fmt.Fprintln(os.Stderr, "  Supported keywords include:")
		kernelNames := etw.GetKernelProviderNames()
		sort.Strings(kernelNames)
		for i := 0; i < len(kernelNames); i += 4 {
			end := min(i+4, len(kernelNames))
			fmt.Fprintf(os.Stderr, "    %s\n", strings.Join(kernelNames[i:end], ", "))
		}

		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  etwread -p \"Microsoft-Windows-Kernel-File:0xff:12,13,14\"")
		fmt.Fprintln(os.Stderr, "  etwread -kernel Process,Thread,CSwitch")
		fmt.Fprintln(os.Stderr, "  etwread -kernel Process -kernel-ids 1,2,5 # Trace Process start/stop/rundown events")
		fmt.Fprintln(os.Stderr, "  etwread -etl C:\\path\\to\\trace.etl") // TODO: filtering on ETL files?
		fmt.Fprintln(os.Stderr, "  etwread -p Microsoft-Windows-DNS-Client -debug lite")
	}

	flag.Parse()

	if help {
		flag.Usage()
		return nil
	}

	// 2. Flag Validation
	modeCount := 0
	if len(providers) > 0 {
		modeCount++
	}
	if etlFile != "" {
		modeCount++
	}
	if kernelProviders != "" {
		modeCount++
	}

	if modeCount == 0 {
		flag.Usage()
		return fmt.Errorf("no trace mode specified. Use -p, -kernel, or -etl")
	}
	if modeCount > 1 {
		flag.Usage()
		return fmt.Errorf("only one trace mode (-p, -kernel, or -etl) can be used at a time")
	}
	if len(kernelEventIDs) > 0 && kernelProviders == "" {
		return fmt.Errorf("-kernel-ids can only be used with -kernel")
	}
	if debugLevel != "" && debugLevel != "lite" && debugLevel != "full" {
		return fmt.Errorf("invalid -debug level: must be 'lite' or 'full'")
	}

	// 3. Signal Handling for Graceful Shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 4. Session and Consumer Setup
	var c *etw.Consumer
	var s *etw.RealTimeSession // To hold the session for deferred cleanup.
	isRealtime := (etlFile == "")

	switch {
	case etlFile != "":
		fmt.Printf("Reading from ETL file: %s\n", etlFile)
		c = etw.NewConsumer(ctx).FromTraceNames(etlFile)

	case kernelProviders != "":
		fmt.Printf("Starting NT Kernel Logger session with providers: %s\n", kernelProviders)
		names := strings.Split(kernelProviders, ",")
		var flags etw.KernelNtFlag
		if len(names) == 1 && strings.EqualFold(names[0], "all") {
			flags = flags.All()
		} else {
			flags = etw.GetKernelProviderFlags(names...)
		}

		if flags == 0 {
			return fmt.Errorf("no valid kernel providers found for '%s'", kernelProviders)
		}

		s = etw.NewKernelRealTimeSession(flags)

	case len(providers) > 0:
		fmt.Printf("Starting real-time session '%s' with %d provider(s)\n", sessionName, len(providers))
		session := etw.NewRealTimeSession(sessionName)
		s = session // Assign to interface for deferred Stop()

		for _, pstr := range providers {
			prov, err := etw.ParseProvider(pstr)
			if err != nil {
				return fmt.Errorf("error parsing provider string '%s': %v", pstr, err)
			}
			if err := session.AddProvider(prov); err != nil {
				return fmt.Errorf("error adding provider '%s': %v", pstr, err)
			}
			fmt.Printf("  - Added provider: %s (%s)\n", prov.Name, prov.GUID.String())
		}
	}
	if s != nil {
		defer s.Stop()
		if err := s.Start(); err != nil {
			return fmt.Errorf("failed to start session: %w", err)
		}
		// FromSessions must be called after Start for real-time sessions.
		c = etw.NewConsumer(ctx).FromSessions(s)
	}

	// 5. Event Processing Goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.ProcessEvents(func(e *etw.Event) error {
			b, err := json.Marshal(e)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling event: %v\n", err)
				return nil // Continue processing other events
			}
			fmt.Println(string(b))
			return nil
		})
	}()

	// 6. Setup Callbacks based on flags
	// Kernel Event ID Filtering
	if len(kernelEventIDs) > 0 {
		idMap := make(map[uint16]struct{}, len(kernelEventIDs))
		for _, id := range kernelEventIDs {
			idMap[id] = struct{}{}
		}
		c.EventRecordCallback = func(er *etw.EventRecord) bool {
			_, found := idMap[er.EventID()]
			return found // Return true if ID is in the map, false otherwise.
		}
	}

	// Debugging Output
	if debugLevel != "" {
		c.EventPreparedCallback = func(h *etw.EventRecordHelper) error {
			switch debugLevel {
			case "lite":
				var userDataHex string
				if h.EventRec.UserDataLength > 0 {
					userDataSlice := unsafe.Slice((*byte)(unsafe.Pointer(h.EventRec.UserData)),
						h.EventRec.UserDataLength)
					userDataHex = hex.EncodeToString(userDataSlice)
				}
				fmt.Printf("[DEBUG] Event: Provider=%s, ID=%d, Opcode=%d, UserDataLen=%d, UserData=%s\n",
					h.EventRec.EventHeader.ProviderId.StringU(),
					h.EventRec.EventHeader.EventDescriptor.Id,
					h.EventRec.EventHeader.EventDescriptor.Opcode,
					h.EventRec.UserDataLength, userDataHex)
			case "full":
				fmt.Println("--- DEBUG EventRecord ---")
				recBytes, _ := json.MarshalIndent(h.EventRec, "", "  ")
				fmt.Println(string(recBytes))
				fmt.Println("--- DEBUG TraceEventInfo ---")
				infoBytes, _ := json.MarshalIndent(h.TraceInfo, "", "  ")
				fmt.Println(string(infoBytes))
				fmt.Println("--------------------------")
			}
			return nil
		}
	}

	// 7. Start Consumption
	defer c.Stop()
	if err := c.Start(); err != nil {
		return fmt.Errorf("error starting consumer: %v", err)
	}

	// 8. Wait for Completion
	if isRealtime {
		fmt.Println("Tracing started. Press Ctrl+C to stop.")
		<-ctx.Done() // Wait for signal
		fmt.Println("\nSignal received, shutting down...")
	} else {
		c.Wait() // Wait for ETL file processing to finish
		fmt.Println("\nETL file processing finished.")
		c.CloseEventsChannel()
	}

	traces := c.GetTraces()

	// 9. Stop and Print Stats
	c.Stop() // Signal consumer to stop processing.
	<-done   // Wait for the event processing goroutine to finish flushing events.

	fmt.Println("\n--- ETW Statistics ---")
	printStats(c, traces)

	if c.LastError() != nil {
		return fmt.Errorf("an error occurred during processing: %v", c.LastError())
	}

	return nil
}

// printStats is a placeholder for printing consumer and trace statistics.
// This is a simplified version of the function from your debug utilities.
func printStats(c *etw.Consumer, traces map[string]*etw.ConsumerTrace) {
	time.Sleep(100 * time.Millisecond) // Give a moment for final stats to update.

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "\nConsumer Total Events Lost:\t%d\n", c.LostEvents.Load())
	fmt.Fprintln(w, strings.Repeat("-", 80))

	for name, trace := range traces {
		fmt.Fprintf(w, "Trace:\t%s\n", name)
		fmt.Fprintf(w, "  Events with Errors:\t%d\n", trace.ErrorEvents.Load())
		fmt.Fprintf(w, "  Properties with Parse Errors:\t%d\n", trace.ErrorPropsParse.Load())
		fmt.Fprintf(w, "  [Callback] Lost Event Notifications:\t%d\n", trace.RTLostEvents.Load())
		fmt.Fprintf(w, "  [Callback] Lost Buffer Notifications:\t%d\n", trace.RTLostBuffer.Load())

		//if trace.IsTraceOpen() {
		if sessionProps, err := trace.QueryTrace(); err == nil {
			fmt.Fprintf(w, "  [Session] Total Events Lost:\t%d\n", sessionProps.EventsLost)
			fmt.Fprintf(w, "  [Session] Buffers Written:\t%d\n", sessionProps.BuffersWritten)
			fmt.Fprintf(w, "  [Session] Buffers Lost:\t%d\n", sessionProps.LogBuffersLost)
		} else {
			fmt.Fprintf(w, "  [Session] Could not query session properties: %v\n", err)
		}
		//}
		fmt.Fprintln(w)
	}
}
