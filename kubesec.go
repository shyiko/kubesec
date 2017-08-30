package main

import (
	"bytes"
	"fmt"
	log "github.com/Sirupsen/logrus"
	kubesec "github.com/shyiko/kubesec/cmd"
	"github.com/shyiko/kubesec/gpg"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"strings"
)

var version string

const template = `apiVersion: v1
kind: Secret
metadata:
  name: __SECRET_NAME__
type: Opaque
data:
  __KEY__: ""
`

func init() {
	log.SetFormatter(&simpleFormatter{})
	log.SetLevel(log.InfoLevel)
}

type simpleFormatter struct{}

func (f *simpleFormatter) Format(entry *log.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	fmt.Fprintf(b, "%s ", entry.Message)
	for k, v := range entry.Data {
		fmt.Fprintf(b, "%s=%+v ", k, v)
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:  "kubesec",
		Long: "Secure secret management for Kubernetes (https://github.com/shyiko/kubesec).",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug, _ := cmd.Flags().GetBool("debug"); debug {
				log.SetLevel(log.DebugLevel)
			}
			if keyring, _ := cmd.Flags().GetString("keyring"); keyring != "" {
				gpg.SetKeyring(keyring)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion, _ := cmd.Flags().GetBool("version"); showVersion {
				fmt.Println(version)
				return nil
			}
			return pflag.ErrHelp
		},
	}
	var keys []string
	buildKeySet := func() (*kubesec.KeySetMutation, error) {
		var keysToAdd []kubesec.Key
		var keysToRemove []kubesec.Key
		changeType := 0
		for _, key := range keys {
			if key == "" {
				continue
			}
			switch key[0] {
			case '+':
				keysToAdd = append(keysToAdd, mustParseKey(strings.TrimPrefix(key, "+")))
				changeType |= 2
			case '-':
				keysToRemove = append(keysToRemove, mustParseKey(strings.TrimPrefix(key, "-")))
				changeType |= 2
			default:
				keysToAdd = append(keysToAdd, mustParseKey(key))
				changeType |= 1
			}
		}
		if changeType == 3 {
			log.Fatal("--key=+.../--key=-... cannot be used together with --key=...")
			return nil, nil
		}
		return &kubesec.KeySetMutation{Replace: changeType == 1, Add: keysToAdd, Remove: keysToRemove}, nil
	}
	encryptCmd := &cobra.Command{
		Use:     "encrypt [file]",
		Aliases: []string{"e"},
		Short:   "Encrypt a Secret (or re-encrypt, possibly with a different set of keys)",
		Long:    "Re/Encrypt a Secret",
		RunE: makeRunE(func(resource []byte, cmd *cobra.Command) ([]byte, error) {
			keySet, err := buildKeySet()
			if err != nil {
				return nil, err
			}
			return kubesec.EncryptWithKeySetMutation(resource, *keySet)
		}),
		Example: "  kubesec encrypt secret.yml\n\n" +
			"  # same as above but output is written back to secret.yml (instead of stdout)\n" +
			"  kubesec encrypt -i secret.yml\n\n" +
			"  # encrypt with specific key (you can specify multiple --key|s if you want)\n" +
			"  kubesec encrypt --key=160A7A9CF46221A56B06AD64461A804F2609FD89 secret.yml\n\n" +
			"  # add ...D89 key & drop ...310 key (leave all other keys untouched) \n" +
			"  kubesec encrypt --key=+160A7A9CF46221A56B06AD64461A804F2609FD89 --key=-72ECF46A56B4AD39C907BBB71646B01B86E50310 secret.yml\n\n`" +
			"  # read from stdin\n" +
			"  cat secret.yml | kubesec encrypt -",
	}
	encryptCmd.Flags().StringArrayVarP(&keys, "key", "k", []string{},
		"PGP fingerprint(s), owner(s) of which will be able to decrypt a Secret "+
			"\n(by default primary (E) PGP fingerprint is used; meaning only the the user who encrypted the secret will be able to decrypt it)")
	editCmd := &cobra.Command{
		Use:     "edit [file]",
		Aliases: []string{"ee"},
		Short:   "Edit a Secret in your $EDITOR (Secret will be automatically re-encrypted upon save)",
		RunE: makeRunE(func(resource []byte, cmd *cobra.Command) ([]byte, error) {
			keySet, err := buildKeySet()
			if err != nil {
				return nil, err
			}
			base64, _ := cmd.Flags().GetBool("base64")
			rotate, _ := cmd.Flags().GetBool("rotate")
			return kubesec.Edit(resource, kubesec.EditOpt{Base64: base64, Rotate: rotate, KeySetMutation: *keySet})
		}),
		Example: "  kubesec edit secret.yml\n" +
			"  cat secret.yml | kubesec edit -",
	}
	editCmd.Flags().BoolP("rotate", "r", false, "Rotate Data Encryption Key")
	editCmd.Flags().BoolP("base64", "b", false, "Keep values in Base64 (by default values are decoded before being passed to the $EDITOR (and then re-encoded on save))")
	editCmd.Flags().BoolP("force", "f", false, "Create Secret if it doesn't exist")
	rootCmd.AddCommand(
		encryptCmd,
		&cobra.Command{
			Use:     "decrypt [file]",
			Aliases: []string{"d"},
			Short:   "Decrypt a Secret",
			RunE: makeRunE(func(resource []byte, cmd *cobra.Command) ([]byte, error) {
				data, _, err := kubesec.Decrypt(resource)
				return data, err
			}),
			Example: "  kubesec decrypt secret.yml\n" +
				"  cat secret.yml | kubesec decrypt -",
		},
		editCmd,
		&cobra.Command{
			Use:     "merge [source] [target]",
			Aliases: []string{"m"},
			Short:   `Superimpose "data" & keys from one Secret over the other`,
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 2 {
					return pflag.ErrHelp
				}
				source, target := args[0], args[1]
				out, err := kubesec.Merge(mustRead(source), mustRead(target))
				if err != nil {
					log.Fatal(err)
				}
				return write(cmd, target, out)
			},
			Example: "  kubesec merge secret.yml -",
		},
		&cobra.Command{
			Use:     "introspect [file]",
			Aliases: []string{"i"},
			Short:   "Show information about the Secret (who has access to the \"data\", etc)",
			RunE: makeRunE(func(resource []byte, cmd *cobra.Command) ([]byte, error) {
				return kubesec.Introspect(resource)
			}),
			Example: "  kubesec introspect secret.yml\n" +
				"  cat secret.yml | kubesec introspect -",
		},
	)
	for _, cmd := range rootCmd.Commands() {
		switch cmd.Name() {
		case "encrypt", "decrypt", "edit":
			cmd.Flags().BoolP("in-place", "i", false, "Write back to [file] (instead of stdout)")
		case "merge":
			cmd.Flags().BoolP("in-place", "i", false, "Write back to [target] (instead of stdout)")
		}
		cmd.Flags().String("keyring", "", "GPG keyring to use")
		cmd.Flags().StringP("output", "o", "", "Redirect output to a file")
	}
	walk(rootCmd, func(cmd *cobra.Command) {
		cmd.Flags().BoolP("help", "h", false, "Print usage")
		cmd.Flags().MarkHidden("help")
	})
	rootCmd.PersistentFlags().Bool("debug", false, "Turn on debug output")
	rootCmd.Flags().Bool("version", false, "Print version information")
	if err := rootCmd.Execute(); err != nil {
		os.Exit(-1)
	}
}

func mustParseKey(key string) kubesec.Key {
	res, err := kubesec.NewKey(key)
	if err != nil {
		log.Fatal(err)
	}
	return *res
}

func walk(cmd *cobra.Command, cb func(*cobra.Command)) {
	cb(cmd)
	for _, c := range cmd.Commands() {
		walk(c, cb)
	}
}

type runE func(cmd *cobra.Command, args []string) error

func makeRunE(fn func([]byte, *cobra.Command) ([]byte, error)) runE {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return pflag.ErrHelp
		}
		file := args[0]
		input, err := read(file)
		force, _ := cmd.Flags().GetBool("force")
		if err != nil {
			if os.IsNotExist(err) && force {
				input = []byte(template)
			} else {
				log.Fatal(err)
			}
		} else if file == "-" && len(input) == 0 && force {
			input = []byte(template)
		}
		out, err := fn(input, cmd)
		if err != nil {
			log.Fatal(err)
		}
		return write(cmd, file, out)
	}
}

func write(cmd *cobra.Command, file string, out []byte) error {
	writeToFile, _ := cmd.Flags().GetBool("in-place")
	if output, _ := cmd.Flags().GetString("output"); output != "" {
		file = output
		writeToFile = true
	}
	if writeToFile && file != "-" {
		return ioutil.WriteFile(file, out, 0600)
	} else {
		fmt.Println(string(out))
		return nil
	}
}

func mustRead(file string) []byte {
	res, err := read(file)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

func read(file string) ([]byte, error) {
	if file == "-" {
		return ioutil.ReadAll(os.Stdin)
	} else {
		return ioutil.ReadFile(file)
	}
}
