package main

import (
	"context"
	"io"
	"os"

	"github.com/function61/gokit/jsonfile"
	"github.com/function61/gokit/ossignal"
	"github.com/function61/id/pkg/idclient"
	"github.com/spf13/cobra"
)

func clientEntry() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "ID client related commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "user-get [serverUrl] [jwt]",
		Short: "Fetch user's details given an auth token",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			serverUrl := args[0]
			if serverUrl == "" {
				serverUrl = idclient.Function61
			}

			exitIfError(userGet(
				ossignal.InterruptOrTerminateBackgroundCtx(nil),
				args[1],
				serverUrl,
				os.Stdout))
		},
	})

	return cmd
}

func userGet(ctx context.Context, token string, serverUrl string, output io.Writer) error {
	client := idclient.New(serverUrl)

	user, err := client.UserByToken(ctx, token)
	if err != nil {
		return err
	}

	return jsonfile.Marshal(os.Stdout, user)
}
