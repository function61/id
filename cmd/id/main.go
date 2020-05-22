package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/function61/gokit/aws/lambdautils"
	"github.com/function61/gokit/dynversion"
	"github.com/function61/gokit/httpauth"
	"github.com/function61/gokit/httputils"
	"github.com/function61/gokit/logex"
	"github.com/function61/gokit/ossignal"
	"github.com/function61/gokit/taskrunner"
	"github.com/spf13/cobra"
)

func main() {
	rootLogger := logex.StandardLogger()

	// AWS Lambda doesn't support giving argv, so we use an ugly hack to detect when
	// we're in Lambda
	if lambdautils.InLambda() {
		lambda.StartHandler(func() lambda.Handler {
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
			exitIfError(runStandaloneRestApi(
				ossignal.InterruptOrTerminateBackgroundCtx(rootLogger),
				rootLogger))
		},
	})

	app.AddCommand(&cobra.Command{
		Use:   "genkey",
		Short: "Generate signing key for a new SSO server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			privateKey, _, err := httpauth.GenerateKey()
			exitIfError(err)

			fmt.Fprintln(os.Stdout, string(privateKey))
		},
	})

	app.AddCommand(clientEntry())

	exitIfError(app.Execute())
}

// for standalone use
func runStandaloneRestApi(ctx context.Context, logger *log.Logger) error {
	handler, err := newHttpHandler()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    ":80",
		Handler: handler,
	}

	tasks := taskrunner.New(ctx, logger)

	tasks.Start("listener "+srv.Addr, func(_ context.Context) error {
		return httputils.RemoveGracefulServerClosedError(srv.ListenAndServe())
	})

	tasks.Start("listenershutdowner", httputils.ServerShutdownTask(srv))

	return tasks.Wait()
}

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
