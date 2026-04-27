package main

import (
	"alertkick-mcp/client"
	"alertkick-mcp/config"
	"alertkick-mcp/tools"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	version   = "0.1.0"
	gitHash   = "unknown"
	gitBranch = "unknown"
	buildTime = "unknown"
)

func main() {
	configFile := flag.String("config", "", "path to config file (optional)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	// stdout is reserved for MCP stdio protocol
	log.SetOutput(os.Stderr)

	if *showVersion {
		fmt.Printf("akmcp %s (git: %s/%s, built: %s)\n", version, gitBranch, gitHash, buildTime)
		os.Exit(0)
	}

	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	log.Printf("akmcp %s starting (api: %s)", version, cfg.APIURL)

	apiClient := client.NewClient(cfg, version)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "alertkick-mcp",
		Version: version,
	}, nil)

	tools.RegisterServerTools(server, apiClient)
	tools.RegisterAlertTools(server, apiClient)
	tools.RegisterSecurityEventTools(server, apiClient)
	tools.RegisterMonitorTools(server, apiClient)
	tools.RegisterHeartbeatTools(server, apiClient)
	tools.RegisterIncidentTools(server, apiClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		log.Println("shutting down")
		cancel()
	}()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
}
