package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rektone666/browsersec/internal/core"
	reportwriter "github.com/rektone666/browsersec/internal/report"
	localserver "github.com/rektone666/browsersec/internal/server"
)

type scanOptions struct {
	OutputDir string
	Browser   string
	NoOpen    bool
	Timeout   time.Duration
}

func main() {
	log.SetFlags(0)
	if len(os.Args) == 1 {
		if err := runScan(scanOptions{OutputDir: defaultOutputDir(), Browser: "default", Timeout: 2 * time.Minute}); err != nil {
			fatal(err)
		}
		return
	}

	switch os.Args[1] {
	case "scan":
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		output := fs.String("output", defaultOutputDir(), "directory where scan reports are created")
		browser := fs.String("browser", "default", "browser to open: default, firefox, chrome, chromium, brave, edge")
		noOpen := fs.Bool("no-open", false, "do not open the scan page or final report automatically")
		timeout := fs.Duration("timeout", 2*time.Minute, "maximum time to wait for the browser scan")
		_ = fs.Parse(os.Args[2:])
		if err := runScan(scanOptions{OutputDir: *output, Browser: *browser, NoOpen: *noOpen, Timeout: *timeout}); err != nil {
			fatal(err)
		}
	case "console":
		runConsole()
	case "modules":
		printModules()
	case "version", "--version", "-v":
		fmt.Printf("BrowserSec Framework v%s\n", core.Version)
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printHelp()
		os.Exit(2)
	}
}

func runScan(options scanOptions) error {
	if options.Timeout < 15*time.Second {
		return errors.New("timeout must be at least 15 seconds")
	}
	outputDir, err := filepath.Abs(options.OutputDir)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	logger := log.New(os.Stderr, "", 0)
	srv, err := localserver.New(logger)
	if err != nil {
		return err
	}
	srv.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	fmt.Println("BrowserSec Framework v" + core.Version)
	fmt.Println("Local scan service: active on 127.0.0.1")
	fmt.Println("Privacy: scan data stays on this computer")
	fmt.Printf("Checks: %d automatic modules\n\n", len(core.Modules))
	fmt.Println("Opening the browser security scan…")

	if !options.NoOpen {
		if err := openBrowser(srv.URL(), options.Browser); err != nil {
			fmt.Printf("Could not open the browser automatically: %v\n", err)
			fmt.Println("Open this local link manually:")
			fmt.Println(srv.URL())
		}
	} else {
		fmt.Println("Open this local link to run the scan:")
		fmt.Println(srv.URL())
	}

	select {
	case payload := <-srv.Results():
		fmt.Println("\nBrowser checks completed. Generating reports…")
		paths, rep, err := reportwriter.Write(outputDir, payload)
		if err != nil {
			return err
		}
		fmt.Printf("Score: %d/100 (%s)\n", rep.OverallScore, rep.Rating)
		fmt.Printf("Report: %s\n", paths.ReportHTML)
		fmt.Printf("JSON:   %s\n", paths.ReportJSON)
		if !options.NoOpen {
			if err := openBrowser(fileURL(paths.ReportHTML), "default"); err != nil {
				fmt.Printf("Could not open the report automatically: %v\n", err)
			}
		}
		return nil
	case <-time.After(options.Timeout):
		return fmt.Errorf("scan timed out after %s; the browser may have been closed or blocked from opening the local page", options.Timeout)
	}
}

func runConsole() {
	reader := bufio.NewScanner(os.Stdin)
	fmt.Printf("BrowserSec Framework v%s interactive console\n", core.Version)
	fmt.Println("Type 'help' for commands.")
	for {
		fmt.Print("browsersec > ")
		if !reader.Scan() {
			fmt.Println()
			return
		}
		line := strings.TrimSpace(reader.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "help":
			fmt.Println("scan                 Run the automatic scan")
			fmt.Println("modules              List available checks")
			fmt.Println("version              Show version")
			fmt.Println("exit, quit           Leave the console")
		case "scan":
			if err := runScan(scanOptions{OutputDir: defaultOutputDir(), Browser: "default", Timeout: 2 * time.Minute}); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "modules":
			printModules()
		case "version":
			fmt.Printf("v%s\n", core.Version)
		case "exit", "quit":
			return
		default:
			fmt.Println("Unknown command. Type 'help'.")
		}
	}
}

func printModules() {
	fmt.Printf("BrowserSec v%s modules (%d)\n\n", core.Version, len(core.Modules))
	lastCategory := ""
	for _, module := range core.Modules {
		if module.Category != lastCategory {
			lastCategory = module.Category
			fmt.Printf("[%s]\n", lastCategory)
		}
		fmt.Printf("  %-24s %s\n", module.ID, module.Name)
	}
}

func printHelp() {
	fmt.Printf(`BrowserSec Framework v%s

Usage:
  browsersec                  Run the automatic scan
  browsersec scan [options]   Run the automatic scan
  browsersec console          Open the interactive console
  browsersec modules          List all checks
  browsersec version          Show version

Scan options:
  --browser default|firefox|chrome|chromium|brave|edge
  --output PATH
  --timeout 2m
  --no-open

The scanner starts and stops its own private loopback service. Users do not need
to install or operate a web server.
`, core.Version)
}

func defaultOutputDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "browsersec-reports"
	}
	return filepath.Join(home, "BrowserSec Reports")
}

func openBrowser(target, browser string) error {
	if browser == "" {
		browser = "default"
	}
	if browser != "default" {
		if command, ok := browserCommand(browser, target); ok {
			return exec.Command(command[0], command[1:]...).Start()
		}
		return fmt.Errorf("browser %q was not found", browser)
	}
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	case "darwin":
		return exec.Command("open", target).Start()
	default:
		return exec.Command("xdg-open", target).Start()
	}
}

func browserCommand(browser, target string) ([]string, bool) {
	candidates := map[string][]string{
		"firefox":  {"firefox", "firefox-esr"},
		"chrome":   {"google-chrome", "google-chrome-stable"},
		"chromium": {"chromium", "chromium-browser"},
		"brave":    {"brave-browser", "brave"},
		"edge":     {"microsoft-edge", "microsoft-edge-stable"},
	}
	for _, name := range candidates[strings.ToLower(browser)] {
		if path, err := exec.LookPath(name); err == nil {
			return []string{path, target}, true
		}
	}
	return nil, false
}

func fileURL(path string) string {
	absolute, _ := filepath.Abs(path)
	absolute = filepath.ToSlash(absolute)
	if runtime.GOOS == "windows" && !strings.HasPrefix(absolute, "/") {
		absolute = "/" + absolute
	}
	return (&url.URL{Scheme: "file", Path: absolute}).String()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}
