package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Organic-Programming/go-holons/pkg/holonrpc"
)

const (
	defaultBindURL = "ws://127.0.0.1:0/rpc"
	defaultSDK     = "c-holons"
	defaultVersion = "0.1.0"
)

type options struct {
	bindURL string
	sdk     string
	version string
	once    bool
}

func main() {
	opts, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	server := holonrpc.NewServer(opts.bindURL)

	handled := make(chan struct{})
	var handledOnce sync.Once
	markHandled := func() {
		handledOnce.Do(func() {
			close(handled)
		})
	}

	var latestClientMu sync.RWMutex
	latestClientID := ""

	server.Register("echo.v1.Echo/Ping", func(_ context.Context, params map[string]any) (map[string]any, error) {
		markHandled()
		out := make(map[string]any, len(params)+2)
		for k, v := range params {
			out[k] = v
		}
		out["sdk"] = opts.sdk
		out["version"] = opts.version
		return out, nil
	})

	server.Register("echo.v1.Echo/CallClient", func(ctx context.Context, params map[string]any) (map[string]any, error) {
		markHandled()
		latestClientMu.RLock()
		clientID := latestClientID
		latestClientMu.RUnlock()
		if clientID == "" {
			return nil, &holonrpc.ResponseError{
				Code:    14,
				Message: "no connected client",
			}
		}

		name := "c"
		if rawName, ok := params["name"].(string); ok {
			trimmed := strings.TrimSpace(rawName)
			if trimmed != "" {
				name = trimmed
			}
		}

		return server.Invoke(ctx, clientID, "client.v1.Client/Hello", map[string]any{"name": name})
	})

	addr, err := server.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "start failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(addr)

	if opts.once {
		select {
		case <-handled:
		case <-time.After(10 * time.Second):
		}

		closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer closeCancel()
		if err := server.Close(closeCtx); err != nil {
			fmt.Fprintf(os.Stderr, "close failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	waitCtx, waitCancel := context.WithCancel(context.Background())
	defer waitCancel()

	go func() {
		for {
			id, waitErr := server.WaitForClient(waitCtx)
			if waitErr != nil {
				return
			}
			latestClientMu.Lock()
			latestClientID = id
			latestClientMu.Unlock()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	signal.Stop(sigCh)
	waitCancel()

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	if err := server.Close(closeCtx); err != nil {
		fmt.Fprintf(os.Stderr, "close failed: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() (options, error) {
	sdk := flag.String("sdk", defaultSDK, "sdk name returned in echo responses")
	version := flag.String("version", defaultVersion, "sdk version returned in echo responses")
	once := flag.Bool("once", false, "exit after handling first client request")
	flag.Parse()

	if flag.NArg() > 1 {
		return options{}, fmt.Errorf("usage: go_holonrpc_server.go [ws://host:port/rpc] [--sdk <name>] [--version <version>]")
	}

	bindURL := defaultBindURL
	if flag.NArg() == 1 {
		bindURL = flag.Arg(0)
	}

	return options{
		bindURL: bindURL,
		sdk:     *sdk,
		version: *version,
		once:    *once,
	}, nil
}
