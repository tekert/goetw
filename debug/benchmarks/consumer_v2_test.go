///go:build windows

package benchmarks

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
	"testing"
	"time"

	//"github.com/goccy/go-json"

	"github.com/tekert/goetw/etw"
)

/*
	# Execute commands from goetw\debug\benchmarks>

	go1.24.5 test -bench="^BenchmarkConsumer2$" -trimpath -benchtime=1x -count=10 ./ -args -profile=base
	go test -bench="^BenchmarkConsumer2$" -trimpath -benchtime=1x -count=10 ./ -args -profile=new
	# (saved ./profiles are relative to this "benchmark" dir test)

	go tool pprof -proto (Get-ChildItem -Path ".\profiles\cpu\base\*.pprof").FullName > ".\profiles\merged_base.pprof"
	go tool pprof -proto (Get-ChildItem -Path ".\profiles\cpu\new\*.pprof").FullName > ".\profiles\merged_new.pprof"

	go tool pprof -http=":" -base ".\profiles\merged_base.pprof" ".\profiles\merged_new.pprof"

	# https://go.dev/doc/pgo
	# https://go.dev/blog/pgo

	go test -bench="^BenchmarkConsumer2$" -trimpath -benchtime=1x -count=10 ./ -args -profile=new
	go tool pprof -proto (Get-ChildItem -Path ".\profiles\cpu\new\*.pprof").FullName > ".\profiles\merged_new.pprof"
	cp .\profiles\merged_new.pprof default.pgo    # optional if new code neds to be tested and repeat go test -c ...

	# Compiling for speed (from goetw\debug>)
	go test -c -pgo .\default.pgo -o .\benchv2.exe -gcflags="all=-B" .\
	.\benchv2.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=10 -profile=cpuprof

	go tool pprof -proto (Get-ChildItem -Path ".\profiles\cpu\cpuprof\*.pprof").FullName > ".\profiles\cpuprof.pprof"
	go tool pprof -http=":" ".\profiles\cpuprof.pprof"
	# we can compare merged pprofs with -base etc.
	# Note, take multiple profiles, pgo works best when it has updated pgo data from multiple runs.

	# view assembly:
	go test -c -pgo .\default.pgo -o .\benchv2.exe -gcflags="github.com/tekert/goetw/etw=-B -S" .\ 2> assembly.txt

	# --- Lower variance measurements (from goetw\debug\benchmarks>) ---
	# -pair: each run is paired with a control run (empty EventRecordCallback, same ETL)
	# in alternating order. Reports delta-ns/event = real - control,
	# i.e. the cost of our code above the ProcessTrace + C->Go transition floor.
	# Only common-mode noise cancels in the delta; most of the noise measured here was not,
	# so the delta alone is not more stable. High priority + affinity (below) is what helps.
	.\benchv2.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=10 -pair

	# Same with High priority, whole process pinned to logical CPU 4 (avoids core 0 interrupts).
	# Much more stable (~1% spread vs ~3-4%) and faster, but note the Go runtime (GC, sysmon)
	# then shares that single CPU with the ProcessTrace thread. Use for A/B, not absolute numbers.
	$p = Start-Process .\benchv2.exe -NoNewWindow -PassThru -ArgumentList '-test.bench=^BenchmarkConsumer2$','-test.benchtime=1x','-test.count=10','-pair'; $p.PriorityClass='High'; $p.ProcessorAffinity=0x10; $p.WaitForExit()

	# A/B with benchstat (use -count=20, interleave binaries if possible):
	.\benchv2-old.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=20 -pair > old.txt
	.\benchv2.exe     -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=20 -pair > new.txt
	go run golang.org/x/perf/cmd/benchstat@latest old.txt new.txt
*/

// > logman start "NT Kernel Logger" -p "Windows Kernel Trace" "(process,thread,img,disk,net,registry,fileio,pf,cswitch)" -o systemevents.etl -ets
const testFile2 = "E:\\Datos\\systemevents.etl"

var (
	// Flags to control profiling.
	cpuProfileNameFlag  = flag.String("profile", "", "Enable CPU profiling (takes effect after first benchmarked run).")
	heapProfileNameFlag = flag.String("heap", "", "Enable heap profiling (takes snapshot after each benchmarked run).")
	pairFlag            = flag.Bool("pair", false, "Pair each run with a control run (empty callback) and report the delta.")

	// Global state for the benchmark run count.
	benchmarkRun atomic.Int32

	totaleventssec float64 = 0.0
	totalDeltaNs   float64 = 0.0
)

// runControl processes the same ETL with an empty EventRecordCallback.
// This is the floor: ProcessTrace + C->Go transition, no parsing.
func runControl() (events int, elapsed time.Duration) {
	c := etw.NewConsumer(context.Background()).FromTraces(testFile2)
	c.EventRecordCallback = func(e *etw.EventRecord) bool {
		events++
		return false
	}
	start := time.Now()
	if err := c.Start(); err != nil {
		panic(err)
	}
	c.Wait()
	if err := c.Stop(); err != nil {
		panic(err)
	}
	elapsed = time.Since(start)
	return events, elapsed
}

// TestMain is the entry point for the test package. It's the standard place
// to parse custom command-line flags before any tests or benchmarks are run.
func TestMain(m *testing.M) {
	flag.Parse()
	fmt.Printf("Date: %s\n", time.Now().Format("2006-01-02 15:04:05")) // Always prints

	rc := m.Run()

	// Print average after all benchmarks have completed.
	runs := int(benchmarkRun.Load())
	if runs > 1 {
		n := float64(runs - 1) // exclude first warm-up run
		fmt.Printf("Average Events/s: %.2f\n", totaleventssec/n)
		if *pairFlag {
			fmt.Printf("Average delta-ns/event: %.2f\n", totalDeltaNs/n)
		}
	}

	os.Exit(rc)
}

func BenchmarkConsumer2(b *testing.B) {
	// Prevent running both profilers at once as they can interfere.
	if *cpuProfileNameFlag != "" && *heapProfileNameFlag != "" {
		b.Fatal("Error: Cannot run CPU and heap profiling simultaneously.")
	}

	runNum := benchmarkRun.Add(1)

	etw.DisableLogging()

	//	b.Run("EtlFileBench", func(b *testing.B) {
	for b.Loop() {
		c := etw.NewConsumer(context.Background()).FromTraces(testFile2)
		defer c.Stop()

		count := 0

		// 4,15m events/s vs krawsetw 4,5m events/s
		c.EventRecordCallback = func(e *etw.EventRecord) bool {
			_ = e
			h, _ := e.GetHelper()
			h.PrepareAll()
			// Find the last non-nil property in the prepared list.
			// The properties are already prepared (offsets found) by the time this callback is called.
			var lastProp *etw.Property
			props := *h.PropertiesByIndex
			for i := len(props) - 1; i >= 0; i-- {
				if props[i] != nil {
					lastProp = props[i]
					break
				}
			}

			// If a last property was found, parse it to a string and discard it.
			// This adds the final parsing cost to the benchmark.
			ss := ""
			if lastProp != nil {
				ss, err := lastProp.FormatToString()
				if err != nil {
					panic(err)
				}
				_ = ss
			}
			_ = ss

			count++
			return false
		}
		c.EventRecordCallback = nil

		// 3m events/s
		// c.EventRecordHelperCallback = func(e *etw.EventRecordHelper) error {
		// 	_ = e
		// 	count++
		// 	//e.Skip()
		// 	return nil
		// }
		c.EventRecordHelperCallback = nil

		// 2,3m events/s
		c.EventPreparedCallback = func(e *etw.EventRecordHelper) error {
			_ = e

			// 1,79m events/s vs krawsetw 0,51m events/s
			// // Find the last non-nil property in the prepared list.
			// // The properties are already prepared (offsets found) by the time this callback is called.
			// var lastProp *etw.Property
			// props := *e.PropertiesByIndex
			// for i := len(props) - 1; i >= 0; i-- {
			// 	if props[i] != nil {
			// 		lastProp = props[i]
			// 		break
			// 	}
			// }

			// // If a last property was found, parse it to a string and discard it.
			// // This adds the final parsing cost to the benchmark.
			// ss := ""
			// if lastProp != nil {
			// 	ss, _ := lastProp.FormatToString()
			// 	_ = ss
			// }
			// _ = ss

			count++
			return nil
		}
		//c.EventPreparedCallback = nil

		// 0,63m events/s without e.release vs krawsetw 0,3m events/s
		// 1.22m events/s with e.release vs krawsetw 0,3m events/s
		// c.EventPreparedCallback = func(e *etw.EventRecordHelper) error {

		// 	b, err := e.MarshalJSON() // 0.94m events/s vs 0.24m external lib marshal json.
		// 	if err != nil {
		// 		return err
		// 	}
		// 	_ = b
		// 	_ = e
		// 	count++
		// 	return nil
		// }

		// Control run (outside timer and profiler). Alternate the order so neither
		// side always gets the warmer caches.
		var ctrlEvents int
		var ctrlElapsed time.Duration
		controlFirst := runNum%2 == 0
		if *pairFlag && controlFirst {
			ctrlEvents, ctrlElapsed = runControl()
		}

		// --- Profiling logic starts here ---
		// We only profile runs after the first one (the warm-up).
		shouldProfile := runNum > 1
		var cpuFile *os.File
		var err error

		if (*cpuProfileNameFlag != "") && shouldProfile {
			// Create a unique directory for this profile name.
			profileDir := fmt.Sprintf("./profiles/cpu/%s", *cpuProfileNameFlag)
			os.MkdirAll(profileDir, 0755)
			cpuFileName := fmt.Sprintf("%s/run%d.pprof", profileDir, runNum)
			cpuFile, err = os.Create(cpuFileName)
			if err != nil {
				b.Fatalf("could not create CPU profile: %v", err)
			}
			// Start profiling just before the timed section.
			pprof.StartCPUProfile(cpuFile)
		}

		// --- Timed section starts here ---
		b.ResetTimer() // Start measuring time

		//c.SetTraceInfoCache(false)

		if err := c.Start(); err != nil {
			panic(err)
		}

		c.Wait() // Wait until etl file is fully processed
		if err := c.Stop(); err != nil {
			panic(err)
		}

		b.StopTimer() // Pause for metrics calculation
		// --- Timed section ends here ---

		if *pairFlag && !controlFirst {
			ctrlEvents, ctrlElapsed = runControl()
		}

		// --- Profiling logic stops here ---
		if (*cpuProfileNameFlag != "") && shouldProfile {
			// Stop profiling immediately after the timed section.
			pprof.StopCPUProfile()
			cpuFile.Close()
		}

		if (*heapProfileNameFlag != "") && shouldProfile {
			// Create a unique directory for this profile name.
			profileDir := fmt.Sprintf("./profiles/heap/%s", *heapProfileNameFlag)
			os.MkdirAll(profileDir, 0755)
			heapFileName := fmt.Sprintf("%s/run%d.pprof", profileDir, runNum)
			heapFile, err := os.Create(heapFileName)

			if err != nil {
				b.Fatalf("could not create heap profile: %v", err)
			}
			runtime.GC() // Get a clean heap snapshot.
			pprof.WriteHeapProfile(heapFile)
			heapFile.Close()
		}

		// --- Report metrics ---
		elapsed := b.Elapsed()
		eventsPerSec := float64(count) / elapsed.Seconds()
		b.ReportMetric(float64(count), "events")
		b.ReportMetric(eventsPerSec, "events/sec")

		var deltaNs float64
		if *pairFlag {
			// Normalize both sides by the control count (all delivered events), so
			// events filtered before the real callback don't skew the delta.
			n := float64(ctrlEvents)
			deltaNs = (float64(elapsed.Nanoseconds()) - float64(ctrlElapsed.Nanoseconds())) / n
			b.ReportMetric(n/ctrlElapsed.Seconds(), "ctrl-events/sec")
			b.ReportMetric(deltaNs, "delta-ns/event")
		}

		if runNum >= 2 {
			totaleventssec = totaleventssec + eventsPerSec
			totalDeltaNs += deltaNs
		}
		b.StartTimer()
	}
	//	})
}

// Results (run in Windows terminal and not VS Code for correct formatting

/*
Benchmark: solo EventPreparedCallback

Go 1.24
Date: 2025-08-13 22:33:19
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        5439872300 ns/op           1014417 events           186478 events/sec
BenchmarkConsumer2-16                  1        1433309500 ns/op           1014417 events           707745 events/sec
BenchmarkConsumer2-16                  1        1432519100 ns/op           1014417 events           708135 events/sec
BenchmarkConsumer2-16                  1        1418773100 ns/op           1014417 events           714996 events/sec
BenchmarkConsumer2-16                  1        1411228900 ns/op           1014417 events           718818 events/sec
BenchmarkConsumer2-16                  1        1407255400 ns/op           1014417 events           720848 events/sec
BenchmarkConsumer2-16                  1        1435048600 ns/op           1014417 events           706887 events/sec
BenchmarkConsumer2-16                  1        1434232600 ns/op           1014417 events           707289 events/sec
BenchmarkConsumer2-16                  1        1437165600 ns/op           1014417 events           705846 events/sec
BenchmarkConsumer2-16                  1        1433255900 ns/op           1014417 events           707771 events/sec
PASS
ok      debug_etw/benchmarks    19.856s

Go 1.24.5
Date: 2025-08-14 09:40:25
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        2936520600 ns/op           1014417 events           345449 events/sec
BenchmarkConsumer2-16                  1        1269584700 ns/op           1014417 events           799015 events/sec
BenchmarkConsumer2-16                  1        1346573700 ns/op           1014417 events           753332 events/sec
BenchmarkConsumer2-16                  1        1259975600 ns/op           1014417 events           805109 events/sec
BenchmarkConsumer2-16                  1        1388099000 ns/op           1014417 events           730796 events/sec
BenchmarkConsumer2-16                  1        1274249500 ns/op           1014417 events           796090 events/sec
BenchmarkConsumer2-16                  1        1313937100 ns/op           1014417 events           772044 events/sec
BenchmarkConsumer2-16                  1        1278233900 ns/op           1014417 events           793608 events/sec
BenchmarkConsumer2-16                  1        1336265300 ns/op           1014417 events           759144 events/sec
BenchmarkConsumer2-16                  1        1267644300 ns/op           1014417 events           800238 events/sec
PASS
ok      debug_etw/benchmarks    14.698s

Go 1.24.5
Date: 2025-08-16 07:44:23
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        2550580800 ns/op           1014417 events           397720 events/sec
BenchmarkConsumer2-16                  1        1255566800 ns/op           1014417 events           807936 events/sec
BenchmarkConsumer2-16                  1        1278653800 ns/op           1014417 events           793348 events/sec
BenchmarkConsumer2-16                  1        1258155500 ns/op           1014417 events           806273 events/sec
BenchmarkConsumer2-16                  1        1246076100 ns/op           1014417 events           814089 events/sec
BenchmarkConsumer2-16                  1        1265799100 ns/op           1014417 events           801405 events/sec
BenchmarkConsumer2-16                  1        1269448000 ns/op           1014417 events           799101 events/sec
BenchmarkConsumer2-16                  1        1258455200 ns/op           1014417 events           806081 events/sec
BenchmarkConsumer2-16                  1        1250738900 ns/op           1014417 events           811054 events/sec
BenchmarkConsumer2-16                  1        1254865400 ns/op           1014417 events           808387 events/sec
PASS
Average Events/s: 805297.11
ok      debug_etw/benchmarks    13.911s

Go 1.24.5
PS E:\Sources\go\projects\goetw\debug> go test -bench="^BenchmarkConsumer2$" -benchtime=1x -count=10 ./benchmarks
Date: 2025-08-18 06:19:29
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        2620829900 ns/op           1014417 events           387059 events/sec
BenchmarkConsumer2-16                  1        1049897400 ns/op           1014417 events           966206 events/sec
BenchmarkConsumer2-16                  1        1046690600 ns/op           1014417 events           969166 events/sec
BenchmarkConsumer2-16                  1        1036535800 ns/op           1014417 events           978661 events/sec
BenchmarkConsumer2-16                  1        1036007900 ns/op           1014417 events           979160 events/sec
BenchmarkConsumer2-16                  1        1028793000 ns/op           1014417 events           986027 events/sec
BenchmarkConsumer2-16                  1        1048314800 ns/op           1014417 events           967665 events/sec
BenchmarkConsumer2-16                  1        1043012800 ns/op           1014417 events           972584 events/sec
BenchmarkConsumer2-16                  1        1038335500 ns/op           1014417 events           976965 events/sec
BenchmarkConsumer2-16                  1        1046452500 ns/op           1014417 events           969387 events/sec
PASS
Average Events/s: 973979.95

Go 1.24.5 con PGO
PS E:\Sources\go\projects\goetw\debug> .\benchmarks\test124pgo.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime=1x" -"test.count"=10
Date: 2025-08-20 10:31:09
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        2492129400 ns/op           1014586 events           407116 events/sec
BenchmarkConsumer2-16                  1         989343600 ns/op           1014586 events          1025514 events/sec
BenchmarkConsumer2-16                  1         985259300 ns/op           1014586 events          1029766 events/sec
BenchmarkConsumer2-16                  1         965995000 ns/op           1014586 events          1050302 events/sec
BenchmarkConsumer2-16                  1         971516900 ns/op           1014586 events          1044332 events/sec
BenchmarkConsumer2-16                  1         979749000 ns/op           1014586 events          1035557 events/sec
BenchmarkConsumer2-16                  1         970643100 ns/op           1014586 events          1045272 events/sec
BenchmarkConsumer2-16                  1         964179300 ns/op           1014586 events          1052280 events/sec
BenchmarkConsumer2-16                  1         978295200 ns/op           1014586 events          1037096 events/sec
BenchmarkConsumer2-16                  1         971094900 ns/op           1014586 events          1044786 events/sec
PASS
Average Events/s: 1040545.00

GO 1.25 reduced performance by 12%... there is something with the maps



31/8/2025 con Go 1.24.5
NOTE: Here I significantly optimized the traceeveninfo and the intergetValues ​​methods I'd been wanting to optimize.
It was somewhat elusive to optimize; I tried preparsing the schema cache to see if the flag for PropertyParamCount was needed.
But I gained 2 points and lost 1, so it occurred to me to change how scalar values ​​are stored for the incoming props.
If we simply use an array of pointers to the props, and when the prop is needed, we request it through the pointer... that's it.
It took me a whole day to optimize that alone, and almost another full day for the schema cache. Too much time. It was a very critical area.



PS E:\Sources\go\projects\goetw\debug> go1.24.5 test -bench="^BenchmarkConsumer2$" -benchtime=1x -count=10 ./benchmarks
Date: 2025-08-31 01:01:23
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        5094065600 ns/op           1014586 events           199170 events/sec
BenchmarkConsumer2-16                  1         894598400 ns/op           1014586 events          1134125 events/sec
BenchmarkConsumer2-16                  1         910441500 ns/op           1014586 events          1114389 events/sec
BenchmarkConsumer2-16                  1         895222700 ns/op           1014586 events          1133334 events/sec
BenchmarkConsumer2-16                  1         912086400 ns/op           1014586 events          1112380 events/sec
BenchmarkConsumer2-16                  1         893699500 ns/op           1014586 events          1135265 events/sec
BenchmarkConsumer2-16                  1         893212500 ns/op           1014586 events          1135884 events/sec
BenchmarkConsumer2-16                  1         895079900 ns/op           1014586 events          1133515 events/sec
BenchmarkConsumer2-16                  1         906156700 ns/op           1014586 events          1119659 events/sec
BenchmarkConsumer2-16                  1         888049100 ns/op           1014586 events          1142489 events/sec
PASS
Average Events/s: 1129004.37
ok      debug_etw/benchmarks    13.210s


Many more optimizations, now I'm really happy with the result.

PS E:\Sources\go\projects\goetw\debug> go test -bench="^BenchmarkConsumer2$" -benchtime=1x -count=10 ./benchmarks
Date: 2025-09-01 09:32:49
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        1937056000 ns/op           1014586 events           523777 events/sec
BenchmarkConsumer2-16                  1         574871300 ns/op           1014586 events          1764893 events/sec
BenchmarkConsumer2-16                  1         582989200 ns/op           1014586 events          1740318 events/sec
BenchmarkConsumer2-16                  1         572103800 ns/op           1014586 events          1773430 events/sec
BenchmarkConsumer2-16                  1         578990000 ns/op           1014586 events          1752338 events/sec
BenchmarkConsumer2-16                  1         582085000 ns/op           1014586 events          1743021 events/sec
BenchmarkConsumer2-16                  1         586438600 ns/op           1014586 events          1730081 events/sec
BenchmarkConsumer2-16                  1         583006000 ns/op           1014586 events          1740267 events/sec
BenchmarkConsumer2-16                  1         584987100 ns/op           1014586 events          1734374 events/sec
BenchmarkConsumer2-16                  1         582335600 ns/op           1014586 events          1742271 events/sec
PASS
Average Events/s: 1746777.04
ok      debug_etw/benchmarks    7.190s

------------------------------------
With PGO and no bound check
> go test -c -pgo .\default.pgo -o .\benchmarks\benchv2.exe -gcflags="all=-B" -ldflags="-s -w" .\benchmarks

PS E:\Sources\go\projects\goetw\debug> .\benchmarks\benchv2.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=10 .\benchmarks
Date: 2025-10-08 19:59:08
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        2195501600 ns/op           1014586 events           462120 events/sec
BenchmarkConsumer2-16                  1         517190800 ns/op           1014586 events          1961726 events/sec
BenchmarkConsumer2-16                  1         506837900 ns/op           1014586 events          2001797 events/sec
BenchmarkConsumer2-16                  1         507104000 ns/op           1014586 events          2000746 events/sec
BenchmarkConsumer2-16                  1         500730700 ns/op           1014586 events          2026213 events/sec
BenchmarkConsumer2-16                  1         510669900 ns/op           1014586 events          1986775 events/sec
BenchmarkConsumer2-16                  1         508267400 ns/op           1014586 events          1996167 events/sec
BenchmarkConsumer2-16                  1         511267200 ns/op           1014586 events          1984454 events/sec
BenchmarkConsumer2-16                  1         508009000 ns/op           1014586 events          1997182 events/sec
BenchmarkConsumer2-16                  1         511527600 ns/op           1014586 events          1983444 events/sec
PASS
Average Events/s: 1993167.11


 slices instead of maps, and fixes for schema cache.

PS E:\Sources\go\projects\goetw\debug> go test -c -pgo .\default.pgo -o .\benchmarks\benchv2-128new.exe -gcflags="all=-B" .\benchmarks
PS E:\Sources\go\projects\goetw\debug> .\benchmarks\benchv2-128new.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=10
Date: 2025-10-11 12:09:58
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        2073511800 ns/op           1014586 events           489308 events/sec
BenchmarkConsumer2-16                  1         476010600 ns/op           1014586 events          2131437 events/sec
BenchmarkConsumer2-16                  1         465048400 ns/op           1014586 events          2181679 events/sec
BenchmarkConsumer2-16                  1         465832100 ns/op           1014586 events          2178008 events/sec
BenchmarkConsumer2-16                  1         471636400 ns/op           1014586 events          2151204 events/sec
BenchmarkConsumer2-16                  1         469822700 ns/op           1014586 events          2159509 events/sec
BenchmarkConsumer2-16                  1         471960600 ns/op           1014586 events          2149727 events/sec
BenchmarkConsumer2-16                  1         468382100 ns/op           1014586 events          2166151 events/sec
BenchmarkConsumer2-16                  1         462531000 ns/op           1014586 events          2193553 events/sec
BenchmarkConsumer2-16                  1         471514900 ns/op           1014586 events          2151759 events/sec
PASS
Average Events/s: 2162558.58


 targeted property reset instead of full  and epi manual advacement in prepare props.

PS E:\Sources\go\projects\goetw\debug> .\benchmarks\benchv2-128new.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=10 -profile=compiledkey128new
Date: 2025-10-11 12:44:17
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        2059539500 ns/op           1014586 events           492628 events/sec
BenchmarkConsumer2-16                  1         441978000 ns/op           1014586 events          2295559 events/sec
BenchmarkConsumer2-16                  1         446081300 ns/op           1014586 events          2274443 events/sec
BenchmarkConsumer2-16                  1         432403400 ns/op           1014586 events          2346388 events/sec
BenchmarkConsumer2-16                  1         432904600 ns/op           1014586 events          2343672 events/sec
BenchmarkConsumer2-16                  1         436140900 ns/op           1014586 events          2326281 events/sec
BenchmarkConsumer2-16                  1         432843600 ns/op           1014586 events          2344002 events/sec
BenchmarkConsumer2-16                  1         426639800 ns/op           1014586 events          2378087 events/sec
BenchmarkConsumer2-16                  1         436816400 ns/op           1014586 events          2322683 events/sec
BenchmarkConsumer2-16                  1         430953100 ns/op           1014586 events          2354285 events/sec
PASS
Average Events/s: 2331711.20

single composite schema key instead of 2 keys (provider+eventid) plus updated PGO.

PS E:\Sources\go\projects\goetw\debug> go test -c -pgo .\default.pgo -o .\benchmarks\benchv2-128new.exe -gcflags="all=-B" .\benchmarks
PS E:\Sources\go\projects\goetw\debug> .\benchmarks\benchv2-128new.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x
-"test.count"=10 -profile=compiledkey128new
Date: 2025-10-12 19:35:31
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        1974085200 ns/op           1014586 events           513953 events/sec
BenchmarkConsumer2-16                  1         396148600 ns/op           1014586 events          2561125 events/sec
BenchmarkConsumer2-16                  1         399489200 ns/op           1014586 events          2539709 events/sec
BenchmarkConsumer2-16                  1         392218000 ns/op           1014586 events          2586793 events/sec
BenchmarkConsumer2-16                  1         399859800 ns/op           1014586 events          2537356 events/sec
BenchmarkConsumer2-16                  1         395857300 ns/op           1014586 events          2563011 events/sec
BenchmarkConsumer2-16                  1         403464700 ns/op           1014586 events          2514684 events/sec
BenchmarkConsumer2-16                  1         396060900 ns/op           1014586 events          2561693 events/sec
BenchmarkConsumer2-16                  1         402352500 ns/op           1014586 events          2521636 events/sec
BenchmarkConsumer2-16                  1         402553900 ns/op           1014586 events          2520374 events/sec
PASS
Average Events/s: 2545153.38

Same es before but with new optimizations from go v1.26  +3.1% improvement.

go v1.26.2
PS E:\Sources\go\projects\goetw\debug> .\benchmarks\benchv2.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=10 -profile=cpuprof
Date: 2026-06-08 22:15:15
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        1730429300 ns/op           1014586 events           586321 events/sec
BenchmarkConsumer2-16                  1         384752100 ns/op           1014586 events          2636988 events/sec
BenchmarkConsumer2-16                  1         377710300 ns/op           1014586 events          2686150 events/sec
BenchmarkConsumer2-16                  1         387996800 ns/op           1014586 events          2614936 events/sec
BenchmarkConsumer2-16                  1         388053400 ns/op           1014586 events          2614555 events/sec
BenchmarkConsumer2-16                  1         403013300 ns/op           1014586 events          2517501 events/sec
BenchmarkConsumer2-16                  1         377865700 ns/op           1014586 events          2685045 events/sec
BenchmarkConsumer2-16                  1         382691200 ns/op           1014586 events          2651189 events/sec
BenchmarkConsumer2-16                  1         393186900 ns/op           1014586 events          2580418 events/sec
BenchmarkConsumer2-16                  1         383019700 ns/op           1014586 events          2648915 events/sec
PASS
Average Events/s: 2626188.52


go v1.27.3
PS E:\Sources\go\projects\goetw\debug\benchmarks> .\benchv2.exe -"test.bench"="^BenchmarkConsumer2$" -"test.benchtime"=1x -"test.count"=10 -profile=cpuprof
Date: 2026-10-20 16:33:23
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2-16                  1        2020655800 ns/op           1014586 events           502107 events/sec
BenchmarkConsumer2-16                  1         355156900 ns/op           1014586 events          2856729 events/sec
BenchmarkConsumer2-16                  1         354960700 ns/op           1014586 events          2858308 events/sec
BenchmarkConsumer2-16                  1         357883000 ns/op           1014586 events          2834968 events/sec
BenchmarkConsumer2-16                  1         350647700 ns/op           1014586 events          2893465 events/sec
BenchmarkConsumer2-16                  1         350803000 ns/op           1014586 events          2892186 events/sec
BenchmarkConsumer2-16                  1         352648400 ns/op           1014586 events          2877049 events/sec
BenchmarkConsumer2-16                  1         363949700 ns/op           1014586 events          2787712 events/sec
BenchmarkConsumer2-16                  1         365782900 ns/op           1014586 events          2773740 events/sec
BenchmarkConsumer2-16                  1         366794000 ns/op           1014586 events          2766094 events/sec
PASS
Average Events/s: 2837805.66

Perf changes in code have improved the performance by 8%

go v1.27.3 (same as above)
but with high priority and processor affinity to core 4 (0x10) to avoid context switching and other processes running on the same core.
PS E:\Sources\go\projects\goetw\debug\benchmarks> $p = Start-Process .\benchv2.exe -NoNewWindow -PassThru -ArgumentList '-test.bench=^BenchmarkConsumer2$','-test.benchtime=1x','-test.count=10','-pair'; $p.PriorityClass='High'; $p.ProcessorAffinity=0x10; $p.WaitForExit()
Date: 2026-10-29 01:38:37
goos: windows
goarch: amd64
pkg: debug_etw/benchmarks
cpu: AMD Ryzen 7 5700X3D 8-Core Processor
BenchmarkConsumer2             1        2107290900 ns/op           4352860 ctrl-events/sec            2389 cycles/event       1709 delta-cyc/event            1847 delta-ns/event          1014586 events           481465 events/sec
BenchmarkConsumer2             1         373814900 ns/op           4325879 ctrl-events/sec            1094 cycles/event        411.8 delta-cyc/event           137.3 delta-ns/event        1014586 events          2714142 events/sec
BenchmarkConsumer2             1         374264600 ns/op           4346397 ctrl-events/sec            1094 cycles/event        414.7 delta-cyc/event           138.8 delta-ns/event        1014586 events          2710881 events/sec
BenchmarkConsumer2             1         382462600 ns/op           4366998 ctrl-events/sec            1117 cycles/event        440.6 delta-cyc/event           148.0 delta-ns/event        1014586 events          2652773 events/sec
BenchmarkConsumer2             1         378978000 ns/op           4363116 ctrl-events/sec            1108 cycles/event        432.3 delta-cyc/event           144.3 delta-ns/event        1014586 events          2677167 events/sec
BenchmarkConsumer2             1         372906300 ns/op           4333343 ctrl-events/sec            1091 cycles/event        410.3 delta-cyc/event           136.8 delta-ns/event        1014586 events          2720755 events/sec
BenchmarkConsumer2             1         372729700 ns/op           4363685 ctrl-events/sec            1090 cycles/event        413.1 delta-cyc/event           138.2 delta-ns/event        1014586 events          2722044 events/sec
BenchmarkConsumer2             1         372325200 ns/op           4344123 ctrl-events/sec            1089 cycles/event        413.7 delta-cyc/event           136.8 delta-ns/event        1014586 events          2725002 events/sec
BenchmarkConsumer2             1         376926000 ns/op           4369605 ctrl-events/sec            1102 cycles/event        425.7 delta-cyc/event           142.7 delta-ns/event        1014586 events          2691740 events/sec
BenchmarkConsumer2             1         372257300 ns/op           4346531 ctrl-events/sec            1089 cycles/event        409.1 delta-cyc/event           136.8 delta-ns/event        1014586 events          2725499 events/sec
PASS
Average Events/s: 2704444.86
Average cycles/event: 1097.01
Average delta-ns/event: 139.96
Average delta-cyc/event: 419.06

*/
