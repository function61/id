package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/function61/gokit/jsonfile"
	"github.com/function61/gokit/osutil"
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
			osutil.ExitIfError(userGet(
				osutil.CancelOnInterruptOrTerminate(nil),
				args[1],
				serverUrlOrDefaultToFunction61(args[0]),
				os.Stdout))
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "pubkey [serverUrl]",
		Short: "Fetch public key for the SSO server",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			osutil.ExitIfError(func() error {
				client := idclient.New(serverUrlOrDefaultToFunction61(args[0]))

				pubKey, err := client.ObtainPublicKey(osutil.CancelOnInterruptOrTerminate(nil))
				if err != nil {
					return err
				}

				fmt.Println(base64.RawURLEncoding.EncodeToString(pubKey))

				return nil
			}())
		},
	})

	return cmd
}

func serverUrlOrDefaultToFunction61(serverUrl string) string {
	if serverUrl != "" {
		return serverUrl
	} else {
		return idclient.Function61
	}
}

func userGet(ctx context.Context, token string, serverUrl string, output io.Writer) error {
	client := idclient.New(serverUrl)

	user, err := client.UserByToken(ctx, token)
	if err != nil {
		return err
	}

	return jsonfile.Marshal(os.Stdout, user)
}
