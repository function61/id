package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/function61/gokit/app/aws/lambdautils"
	"github.com/function61/gokit/app/dynversion"
	"github.com/function61/gokit/log/logex"
	"github.com/function61/gokit/net/http/httputils"
	"github.com/function61/gokit/os/osutil"
	"github.com/spf13/cobra"
)

func main() {
	rootLogger := logex.StandardLogger()

	// AWS Lambda doesn't support giving argv, so we use an ugly hack to detect when
	// we're in Lambda
	if lambdautils.InLambda() {
		lambda.Start(func() lambda.Handler {
			httpHandler, err := newHttpHandler()
			if err != nil {
				// cannot exit in a normal way - we've to handle errors with Lambda's semantics
				// if we want any visibility into errors in Lambda
				return lambdaStaticErrorHandler(err, rootLogger)
			}

			return lambdautils.NewLambdaHttpHandlerAdapter(httpHandler)
		}())
		return // shouldn't ever reach here
	}

	app := &cobra.Command{
		Use:     os.Args[0],
		Short:   "SSO server",
		Version: dynversion.Version,
	}

	app.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Start the standalone server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			osutil.ExitIfError(runStandaloneRestApi(
				osutil.CancelOnInterruptOrTerminate(rootLogger)))
		},
	})

	app.AddCommand(&cobra.Command{
		Use:   "genkey",
		Short: "Generate signing key for a new SSO server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			osutil.ExitIfError(func() error {
				_, ed25519Privkey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return err
				}

				_, err = fmt.Fprintln(os.Stdout, marshalPrivateKey(ed25519Privkey))
				return err
			}())
		},
	})

	app.AddCommand(clientEntry())

	osutil.ExitIfError(app.Execute())
}

// for standalone use
func runStandaloneRestApi(ctx context.Context) error {
	handler, err := newHttpHandler()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    ":80",
		Handler: handler,

		ReadHeaderTimeout: httputils.DefaultReadHeaderTimeout,
	}

	return httputils.CancelableServer(ctx, srv, srv.ListenAndServe)
}

// TODO: move to lambdautils?
type errorLambdaHandler struct {
	error
}

func lambdaStaticErrorHandler(err error, logger *log.Logger) *errorLambdaHandler {
	logex.Levels(logger).Error.Println(err)

	return &errorLambdaHandler{err}
}

func (e *errorLambdaHandler) Invoke(_ context.Context, _ []byte) ([]byte, error) {
	return nil, e.error
}
