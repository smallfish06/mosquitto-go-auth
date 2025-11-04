package backends

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log/slog"
	"strconv"
	"time"

	grpcLogging "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/pkg/errors"
	gs "github.com/smallfish06/mosquitto-go-auth/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GRPC holds a client for the service and implements the Backend interface.
type GRPC struct {
	client           gs.AuthServiceClient
	conn             *grpc.ClientConn
	disableSuperuser bool
	dialOptions      []grpc.DialOption
	hostname         string
	timeout          int
	name             string
}

const defaultGRPCTimeoutMs = 500

// NewGRPC tries to connect to the gRPC service at the given host.
func NewGRPC(authOpts map[string]string) (*GRPC, error) {
	g := &GRPC{
		timeout: defaultGRPCTimeoutMs,
	}

	if authOpts["grpc_host"] == "" || authOpts["grpc_port"] == "" {
		return nil, errors.New("grpc must have a host and port")
	}

	if authOpts["grpc_disable_superuser"] == "true" {
		g.disableSuperuser = true
	}

	if timeout, ok := authOpts["grpc_dial_timeout_ms"]; ok {
		timeoutMs, err := strconv.Atoi(timeout)

		if err != nil {
			slog.Warn("invalid grpc dial timeout value", "error", err)
		} else {
			g.timeout = timeoutMs
		}
	}

	caCert := authOpts["grpc_ca_cert"]
	tlsCert := authOpts["grpc_tls_cert"]
	tlsKey := authOpts["grpc_tls_key"]
	addr := fmt.Sprintf("%s:%s", authOpts["grpc_host"], authOpts["grpc_port"])
	withBlock := authOpts["grpc_fail_on_dial_error"] == "true"

	options, err := setup(addr, caCert, tlsCert, tlsKey, withBlock)
	if err != nil {
		return nil, err
	}

	g.dialOptions = options
	g.hostname = addr

	err = g.initClient()
	if err != nil {
		return nil, err
	}

	return g, nil
}

// GetUser checks that the username exists and the given password hashes to the same password.
func (o *GRPC) GetUser(username, password, clientid string) (bool, error) {
	req := gs.GetUserRequest{
		Username: username,
		Password: password,
		Clientid: clientid,
	}

	resp, err := o.client.GetUser(context.Background(), &req)

	if err != nil {
		slog.Error("grpc get user error", "error", err)
		return false, err
	}

	return resp.Ok, nil

}

// GetSuperuser checks that the user is a superuser.
func (o *GRPC) GetSuperuser(username string) (bool, error) {
	if o.disableSuperuser {
		return false, nil
	}

	req := gs.GetSuperuserRequest{
		Username: username,
	}

	resp, err := o.client.GetSuperuser(context.Background(), &req)

	if err != nil {
		slog.Error("grpc get superuser error", "error", err)
		return false, err
	}

	return resp.Ok, nil

}

// CheckAcl checks if the user has access to the given topic.
func (o *GRPC) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	req := gs.CheckAclRequest{
		Username: username,
		Topic:    topic,
		Clientid: clientid,
		Acc:      acc,
	}

	resp, err := o.client.CheckAcl(context.Background(), &req)

	if err != nil {
		slog.Error("grpc check acl error", "error", err)
		return false, err
	}

	return resp.Ok, nil

}

// GetName gets the gRPC backend's name.
func (o *GRPC) GetName() string {
	if len(o.name) == 0 {
		resp, err := o.client.GetName(context.Background(), &emptypb.Empty{})

		if err != nil {
			o.name = "gRPC"
		} else {
			o.name = resp.Name
		}
	}

	return o.name
}

// Halt signals the gRPC backend that mosquitto is halting.
func (o *GRPC) Halt() {
	_, err := o.client.Halt(context.Background(), &emptypb.Empty{})
	if err != nil {
		slog.Error("grpc halt", "error", err)
	}

	if o.conn != nil {
		o.conn.Close()
	}
}

// interceptorLogger adapts slog logger to grpc logging interface
func interceptorLogger(l *slog.Logger) grpcLogging.Logger {
	return grpcLogging.LoggerFunc(func(ctx context.Context, lvl grpcLogging.Level, msg string, fields ...any) {
		var slogLevel slog.Level
		switch lvl {
		case grpcLogging.LevelDebug:
			slogLevel = slog.LevelDebug
		case grpcLogging.LevelInfo:
			slogLevel = slog.LevelInfo
		case grpcLogging.LevelWarn:
			slogLevel = slog.LevelWarn
		case grpcLogging.LevelError:
			slogLevel = slog.LevelError
		default:
			panic(fmt.Sprintf("unknown level %v", lvl))
		}
		l.Log(ctx, slogLevel, msg, fields...)
	})
}

func setup(hostname string, caCert string, tlsCert string, tlsKey string, withBlock bool) ([]grpc.DialOption, error) {
	logger := slog.Default()
	loggerOpts := []grpcLogging.Option{
		grpcLogging.WithLogOnEvents(grpcLogging.StartCall, grpcLogging.FinishCall),
	}

	nsOpts := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(
			grpcLogging.UnaryClientInterceptor(interceptorLogger(logger), loggerOpts...),
		),
	}

	if withBlock {
		nsOpts = append(nsOpts, grpc.WithBlock())
	}

	if len(caCert) == 0 {
		nsOpts = append(nsOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		slog.Warn("creating insecure grpc client", "server", hostname)
	} else {
		slog.Info("creating grpc client", "server", hostname)

		caCertBytes, err := ioutil.ReadFile(caCert)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("could not load grpc ca certificate (grpc_ca_cert) from file (%s)", caCert))
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertBytes) {
			return nil, errors.New("append ca cert to pool error. Maybe the ca file (grpc_ca_cert) does not contain a valid x509 certificate")
		}
		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
		}

		if len(tlsCert) != 0 && len(tlsKey) != 0 {
			cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if err != nil {
				return nil, errors.Wrap(err, "load x509 keypair error")
			}
			certificates := []tls.Certificate{cert}
			tlsConfig.Certificates = certificates
		} else if len(tlsCert) != 0 || len(tlsKey) != 0 {
			slog.Warn("gRPC backend warning: mutual TLS was disabled due to missing client certificate (grpc_tls_cert) or client key (grpc_tls_key)")
		}

		nsOpts = append(nsOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}

	return nsOpts, nil
}

func (g *GRPC) initClient() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(g.timeout)*time.Millisecond)
	defer cancel()

	gsClient, err := grpc.DialContext(ctx, g.hostname, g.dialOptions...)

	if err != nil {
		return err
	}

	g.conn = gsClient
	g.client = gs.NewAuthServiceClient(gsClient)

	return nil
}
