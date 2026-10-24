// policy-eval is an offline replay tool. It cannot authorize or execute actions.
//
// Optional: -report https://river3.example posts VIOLATION / REVIEW decisions to the
// River3 API as incidents (shadow mode is still forced). The machine token is read from
// the RIVER3_POLICY_TOKEN environment variable, never from a flag, so it doesn't show in `ps`.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	policy "river3.local/policy"
	"river3.local/policy/report"
)

type input struct {
	Profile string       `json:"profile"`
	Event   policy.Event `json:"event"`
}

func run(dir string, inputStream io.Reader, outputStream io.Writer) error {
	return runWith(context.Background(), dir, inputStream, outputStream, nil)
}

func runWith(ctx context.Context, dir string, inputStream io.Reader, outputStream io.Writer, rep *report.Reporter) error {
	loaded, err := policy.LoadProfiles(dir)
	if err != nil {
		return err
	}
	names := []string{}
	for n := range loaded {
		names = append(names, n)
	}
	sort.Strings(names)
	list := []policy.Profile{}
	for _, n := range names {
		p := *loaded[n]
		p.Mode = policy.Shadow
		list = append(list, p)
	}
	engine, err := policy.NewEngine(list, policy.Options{})
	if err != nil {
		return err
	}
	enrolled := map[string]bool{}
	scanner := bufio.NewScanner(inputStream)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	encoder := json.NewEncoder(outputStream)
	line := 0
	for scanner.Scan() {
		line++
		var in input
		if err := policy.DecodeStrict(scanner.Bytes(), &in); err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		p, ok := loaded[in.Profile]
		if !ok {
			return fmt.Errorf("line %d: unknown profile", line)
		}
		// No stdin flag can impersonate authenticated controller context.
		pctx := policy.Context{ProfileName: in.Profile, ProfileVersion: p.Version, Now: time.Now().UTC()}
		d, err := engine.Evaluate(in.Event, pctx)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if err = encoder.Encode(d); err != nil {
			return err
		}
		if rep != nil {
			asset := in.Event.Identity.AssetID
			if !enrolled[asset] {
				w := report.Workload{ID: asset, Name: asset, Profile: p.Name, Kind: p.Kind}
				if err := rep.EnsureWorkload(ctx, w); err != nil {
					return fmt.Errorf("line %d: enroll %s: %w", line, asset, err)
				}
				enrolled[asset] = true
			}
			if _, err := rep.Report(ctx, in.Event, d, p.Kind); err != nil {
				return fmt.Errorf("line %d: report: %w", line, err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if rep != nil {
		s := rep.Stats()
		fmt.Fprintf(os.Stderr, "reported: posted=%d duplicates=%d skipped_in_scope=%d skipped_unknown=%d failed=%d\n",
			s.Posted, s.Duplicates, s.SkippedInScope, s.SkippedUnknown, s.Failed)
	}
	return nil
}

func main() {
	dir := flag.String("profiles", "examples/profiles", "profile JSON directory")
	reportURL := flag.String("report", "", "River3 API base URL; posts VIOLATION/REVIEW decisions as incidents")
	reportUnknown := flag.Bool("report-unknown", false, "also post UNKNOWN decisions (noisy without trusted context)")
	flag.Parse()
	var rep *report.Reporter
	if *reportURL != "" {
		var err error
		rep, err = report.New(report.Config{BaseURL: *reportURL, Token: os.Getenv("RIVER3_POLICY_TOKEN"),
			ReportUnknown: *reportUnknown})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if err := runWith(context.Background(), *dir, os.Stdin, os.Stdout, rep); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
