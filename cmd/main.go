package main

import (
	"alertkick-mcp/client"
	"alertkick-mcp/config"
	"alertkick-mcp/httpserver"
	"alertkick-mcp/tools"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		log.Println("shutting down")
		cancel()
	}()

	// Hosted multi-tenant connector: streamable HTTP + OAuth resource
	// server behind mcp.{domain}. Selected by AKMCP_HTTP_ADDR / http_addr.
	if cfg.HTTPMode() {
		if err := httpserver.New(cfg, version).Run(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
			os.Exit(1)
		}
		return
	}

	// Classic stdio mode: single tenant, X-API-Key.
	log.Printf("akmcp %s starting (api: %s)", version, cfg.APIURL)

	apiClient := client.NewClient(cfg, version)

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "alertkick-mcp",
		Version: version,
	}, nil)

	tools.RegisterAll(server, apiClient)

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Printf("server error: %v", err)
		os.Exit(1)
	}
}
