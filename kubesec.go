package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/shyiko/kubesec/cli"
	kubesec "github.com/shyiko/kubesec/cmd"
	"github.com/shyiko/kubesec/gpg"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

var version string

const resourceTemplate = `apiVersion: v1
data:
  _: _
kind: Secret
metadata:
  name: _
type: Opaque
`

var dataKeyRegexp = regexp.MustCompile("^[0-9a-zA-Z._-]+$")

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
	completion := cli.NewCompletion()
	completed, err := completion.Execute()
	if err != nil {
		log.Debug(err)
		os.Exit(3)
	}
	if completed {
		os.Exit(0)
	}
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
		RunE: makeRunE(func(resource []byte, cmd *cobra.Command) (data []byte, err error) {
			keySet, err := buildKeySet()
			if err != nil {
				return nil, err
			}
			parent, err := cmd.Flags().GetString("parent")
			if err != nil {
				return nil, err
			}
			if parent != "" {
				keySet.Parent = mustRead(parent)
			}
			if cleartext, _ := cmd.Flags().GetBool("cleartext"); cleartext {
				data, err = kubesec.EncryptCleartext(resource, *keySet)
			} else {
				data, err = kubesec.Encrypt(resource, *keySet)
			}
			return
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
		"PGP fingerprint(s)/Google Cloud KMS key(s)/AWS KMS key(s), owner(s) of which will be able to decrypt a Secret "+
			"\n(by default primary (E) PGP fingerprint is used; meaning only the the user who encrypted the secret will be able to decrypt it)")
	encryptCmd.Flags().Bool("cleartext", false, "base64-encode \"data\"")
	encryptCmd.Flags().StringP("parent", "p", "", "path/to/encrypted/secret.enc.yml from which to inherit keys, DEK (!) and IVs (when safe)")
	decryptCmd := &cobra.Command{
		Use:     "decrypt [file]",
		Aliases: []string{"d"},
		Short:   "Decrypt a Secret",
		RunE: makeRunE(func(resource []byte, cmd *cobra.Command) (data []byte, err error) {
			if cleartext, _ := cmd.Flags().GetBool("cleartext"); cleartext {
				data, _, err = kubesec.DecryptCleartext(resource)
			} else {
				data, _, err = kubesec.Decrypt(resource)
			}
			if err != nil {
				log.Fatal(err)
			}
			if tpl, _ := cmd.Flags().GetString("template"); tpl != "" {
				t, err := template.New("template").Option("missingkey=error").Parse(tpl)
				if err != nil {
					log.Fatal(err)
				}
				m := make(map[interface{}]interface{})
				if err := yaml.Unmarshal(data, &m); err != nil {
					log.Fatal(err)
				}
				buf := &bytes.Buffer{}
				if err := t.Execute(buf, m); err != nil {
					log.Fatal(err)
				}
				data = buf.Bytes()
			}
			return
		}),
		Example: "  kubesec decrypt secret.enc.yml\n" +
			"  cat secret.enc.yml | kubesec decrypt -\n\n" +
			"  kubesec decrypt secret.enc.yml --cleartext --template='KEY={{ .data.KEY }}'\n" +
			"  kubesec decrypt secret.enc.yml --cleartext --template=$'#comment separated by a newline\\nKEY={{ .data.KEY }}'",
	}
	decryptCmd.Flags().String("template", "", "Go Template (http://golang.org/pkg/text/template) string for the output")
	decryptCmd.Flags().Bool("cleartext", false, "base64-decode \"data\"")
	createCmd := &cobra.Command{
		Use:     "create [name]",
		Aliases: []string{"c"},
		Short:   "Create a Secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return pflag.ErrHelp
			}
			name := args[0]
			data, err := gatherData(cmd)
			if err != nil {
				return err
			}
			metadata, err := gatherMetadata(cmd)
			if err != nil {
				return err
			}
			if metadata["name"] == nil {
				metadata["name"] = name
			} else if metadata["name"] != name {
				log.Fatalf(`name "%s" and --metadata name "%s" differ`, name, metadata["name"])
			}
			base64encData := make(map[string]string, len(data))
			for key, value := range data {
				base64encData[key] = base64.StdEncoding.EncodeToString(value)
			}
			resource, err := yaml.Marshal(map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata":   metadata,
				"type":       "Opaque",
				"data":       base64encData,
			})
			if err != nil {
				log.Fatal(err)
			}
			keySet, err := buildKeySet()
			if err != nil {
				log.Fatal(err)
			}
			if output, _ := cmd.Flags().GetString("output"); output != "" && output != "-" {
				if force, _ := cmd.Flags().GetBool("force"); !force {
					if _, err := os.Stat(output); err == nil {
						log.Fatalf("%s exists (use --force/-f to override)", output)
					}
				}
			}
			out, err := kubesec.Encrypt(resource, *keySet)
			if err != nil {
				log.Fatal(err)
			}
			return write(cmd, "-", out)
		},
		Example: "  kubesec create secret-name \\\n" +
			"    --data key=value \\\n" +
			"    --data file:pki/ca.crt \\\n" +
			"    --data file:key.pem=pki/private/server.key",
	}
	createCmd.Flags().BoolP("force", "f", false, "Override Secret if it already exists")
	/*
		createCmd.Flags().StringArray("from-literal", nil, "KEY=VALUE pair to include in secret's data")
		createCmd.Flags().StringArray("from-file", nil, "path/to/yoursecretfile file to be included in a secret as \"yoursecretfile\"\n"+
			" (custom key (say mykey) can be specified like so: --from-file=mykey=path/to/a/file)")
	*/
	createCmd.Flags().StringArrayP("metadata", "m", nil, "Secret \"metadata\" key=value to set (e.g. -m name=update-secret-name)")
	createCmd.Flags().StringArrayP("annotation", "a", nil, "Secret \"metadata.annotations\" to set (e.g. -a origin=http://... -a version=...)")
	createCmd.Flags().StringArrayP("label", "l", nil, "Secret \"metadata.labels\" to set (e.g. -l foo=bar -l baz=qux)")
	createCmd.Flags().StringArrayP("data", "d", nil, "Secret \"data\" key=value to set.\n"+
		"To reference a file prepend \"file:\", e.g. -d file:pki/ca.crt or -d file:key=pki/ca.crt.")
	createCmd.Flags().StringArrayVarP(&keys, "key", "k", []string{},
		"PGP fingerprint(s)/Google Cloud KMS key(s)/AWS KMS key(s), owner(s) of which will be able to decrypt a Secret "+
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
			recomputeMAC, _ := cmd.Flags().GetBool("recompute-mac")
			base64, _ := cmd.Flags().GetBool("base64")
			rotate, _ := cmd.Flags().GetBool("rotate")
			return kubesec.Edit(resource, kubesec.EditOpt{Base64: base64, Rotate: rotate, KeySetMutation: *keySet, RecomputeMAC: recomputeMAC})
		}),
		Example: "  kubesec edit secret.enc.yml\n" +
			"  cat secret.enc.yml | kubesec edit -",
	}
	editCmd.Flags().StringArrayVarP(&keys, "key", "k", []string{},
		"PGP fingerprint(s)/Google Cloud KMS key(s)/AWS KMS key(s), owner(s) of which will be able to decrypt a Secret "+
			"\n(by default primary (E) PGP fingerprint is used; meaning only the the user who encrypted the secret will be able to decrypt it)")
	editCmd.Flags().Bool("recompute-mac", false, "Recompute MAC")
	editCmd.Flags().BoolP("rotate", "r", false, "Rotate DEK (Data Encryption Key)")
	editCmd.Flags().BoolP("base64", "b", false, "Keep values in Base64 (by default values are decoded before being passed to the $EDITOR (and then re-encoded on save))")
	editCmd.Flags().BoolP("force", "f", false, "Create Secret if it doesn't exist")
	patchCmd := &cobra.Command{
		Use:     "patch [file]",
		Aliases: []string{"p"},
		Short:   "Update a Secret",
		RunE: makeRunE(func(resource []byte, cmd *cobra.Command) ([]byte, error) {
			keySet, err := buildKeySet()
			if err != nil {
				return nil, err
			}
			metadata, err := gatherTopLevelMetadata(cmd)
			if err != nil {
				return nil, err
			}
			annotations, err := getFlagAsMap(cmd, "annotation")
			if err != nil {
				return nil, err
			}
			labels, err := getFlagAsMap(cmd, "label")
			if err != nil {
				return nil, err
			}
			rotate, _ := cmd.Flags().GetBool("rotate")
			data, err := gatherData(cmd)
			if err != nil {
				return nil, err
			}
			return kubesec.Patch(resource, kubesec.PatchOpt{
				Metadata:              metadata,
				Annotations:           annotations,
				Labels:                labels,
				ClearTextDataMutation: data,
				KeySetMutation:        *keySet,
				Rotate:                rotate,
			})
		}),
		Example: "  kubesec patch secret.enc.yml --data key1=secret_string --data file:key2=path/to/file\n" +
			"  # same as above but output is written back to secret.enc.yml (instead of stdout)\n" +
			"  kubesec patch -i secret.enc.yml --data key1=secret_string --data file:key2=path/to/file\n\n" +
			"  # read from stdin\n" +
			"  cat secret.enc.yml | kubesec patch - --data key1=updated_secret_string",
	}
	/*
		patchCmd.Flags().StringArray("from-literal", nil, "KEY=VALUE pair to include in secret's data")
		patchCmd.Flags().StringArray("from-file", nil, "path/to/yoursecretfile file to be included in a secret as \"yoursecretfile\"\n"+
			" (custom key (say mykey) can be specified like so: --from-file=mykey=path/to/a/file)")
	*/
	patchCmd.Flags().StringArrayP("metadata", "m", nil, "Secret \"metadata\" key=value to set (e.g. -m name=update-secret-name)")
	patchCmd.Flags().StringArrayP("label", "l", nil, "Secret \"metadata.labels\" to set (e.g. -l foo=bar -l baz=qux)")
	patchCmd.Flags().StringArrayP("annotation", "a", nil, "Secret \"metadata.annotations\" to set (e.g. -a origin=http://... -a version=...)")
	patchCmd.Flags().StringArrayP("data", "d", nil, "Secret \"data\" key=value to set.\n"+
		"To reference a file prepend \"file:\", e.g. -d file:pki/ca.crt or -d file:key=pki/ca.crt.\n"+
		"To remove a key prepend \"~\", e.g. -d ~key-to-remove.")
	patchCmd.Flags().StringArrayVarP(&keys, "key", "k", []string{},
		"PGP fingerprint(s)/Google Cloud KMS key(s)/AWS KMS key(s), owner(s) of which will be able to decrypt a Secret "+
			"\n(by default primary (E) PGP fingerprint is used; meaning only the the user who encrypted the secret will be able to decrypt it)")
	patchCmd.Flags().BoolP("rotate", "r", false, "Rotate DEK (Data Encryption Key)")
	completionCmd := &cobra.Command{
		Use:   "completion",
		Short: "Command-line completion",
	}
	completionCmd.AddCommand(
		&cobra.Command{
			Use:   "bash",
			Short: "Generate Bash completion",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 0 {
					return pflag.ErrHelp
				}
				if err := completion.GenBashCompletion(os.Stdout); err != nil {
					log.Error(err)
				}
				return nil
			},
			Example: "  source <(kubesec completion bash)",
		},
		&cobra.Command{
			Use:   "zsh",
			Short: "Generate Z shell completion",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 0 {
					return pflag.ErrHelp
				}
				if err := completion.GenZshCompletion(os.Stdout); err != nil {
					log.Error(err)
				}
				return nil
			},
			Example: "  source <(kubesec completion zsh)",
		},
	)
	rootCmd.AddCommand(
		encryptCmd,
		decryptCmd,
		createCmd,
		editCmd,
		patchCmd,
		completionCmd,
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
			Example: "  kubesec merge source.enc.yml target.yml",
		},
		&cobra.Command{
			Use:     "introspect [file]",
			Aliases: []string{"i"},
			Short:   "Show information about the Secret (who has access to the \"data\", etc)",
			RunE: makeRunE(func(resource []byte, cmd *cobra.Command) ([]byte, error) {
				return kubesec.Introspect(resource)
			}),
			Example: "  kubesec introspect secret.enc.yml\n" +
				"  cat secret.enc.yml | kubesec introspect -",
		},
	)
	for _, cmd := range rootCmd.Commands() {
		switch cmd.Name() {
		case "encrypt", "decrypt", "edit", "patch":
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

func gatherMetadata(cmd *cobra.Command) (map[interface{}]interface{}, error) {
	metadata, err := gatherTopLevelMetadata(cmd)
	if err != nil {
		return nil, err
	}
	m := make(map[interface{}]interface{})
	for key, value := range metadata {
		m[key] = value
	}
	annotations, err := getFlagAsMap(cmd, "annotation")
	if err != nil {
		return nil, err
	}
	if len(annotations) > 0 {
		m["annotations"] = annotations
	}
	labels, err := getFlagAsMap(cmd, "label")
	if err != nil {
		return nil, err
	}
	if len(labels) > 0 {
		m["labels"] = labels
	}
	return m, nil
}

func gatherTopLevelMetadata(cmd *cobra.Command) (map[string]string, error) {
	m, err := getFlagAsMap(cmd, "metadata")
	if err != nil {
		return nil, err
	}
	for key, value := range m {
		if key != "name" && key != "namespace" {
			return nil, errors.New(`--metadata: only "name" and "namespace" are allowed at this time`)
		}
		if value == "" {
			return nil, fmt.Errorf(`--metadata: "%s" cannot be empty`, key)
		}
	}
	return m, nil
}

func getFlagAsMap(cmd *cobra.Command, key string) (map[string]string, error) {
	meta := make(map[string]string)
	entries, _ := cmd.Flags().GetStringArray(key)
	for _, entry := range entries {
		split := strings.SplitN(entry, "=", 2)
		if len(split) != 2 {
			return nil, fmt.Errorf(`--%s: "%s" is not a key=value pair`, key, entry)
		}
		key, value := split[0], split[1]
		meta[key] = value
	}
	return meta, nil
}

func gatherData(cmd *cobra.Command) (map[string][]byte, error) {
	data := make(map[string][]byte)
	entries, _ := cmd.Flags().GetStringArray("data")

	// `kubectl create secret generic` compatibility
	/*
		compatEntries, _ := cmd.Flags().GetStringArray("from-literal")
		compatFileEntries, _ := cmd.Flags().GetStringArray("from-file")
		for _, fileEntry := range compatFileEntries {
			compatEntries = append(compatEntries, "file:" + fileEntry)
		}
		entries = append(compatEntries, entries...)
	*/

	for _, entry := range entries {
		switch {
		case strings.HasPrefix(entry, "file:"):
			split := strings.SplitN(strings.TrimPrefix(entry, "file:"), "=", 2)
			if len(split) == 1 {
				split = []string{filepath.Base(split[0]), split[0]}
			}
			buf, err := ioutil.ReadFile(split[1])
			if err != nil {
				log.Fatal(err)
			}
			data[split[0]] = buf
		case strings.HasPrefix(entry, "~"):
			data[strings.TrimPrefix(entry, "~")] = nil
		default:
			split := strings.SplitN(entry, "=", 2)
			if len(split) != 2 {
				return nil, fmt.Errorf(`--data: "%s" is not a key=value pair`, entry)
			}
			data[split[0]] = []byte(split[1])
		}
	}
	for key := range data {
		mustValidateDataKey(key)
	}
	return data, nil
}

func validateDataKey(key string) error {
	if !dataKeyRegexp.MatchString(key) {
		return fmt.Errorf(`"%s" cannot be used as a "data" key (expected to match /^[0-9a-zA-Z._-]+$/)`, key)
	}
	return nil
}

func mustValidateDataKey(key string) {
	err := validateDataKey(key)
	if err != nil {
		log.Fatal(err)
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
				input = []byte(resourceTemplate)
			} else {
				log.Fatal(err)
			}
		} else if file == "-" && len(input) == 0 && force {
			input = []byte(resourceTemplate)
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
	if writeToFile {
		if tpl, _ := cmd.Flags().GetString("template"); tpl != "" {
			return errors.New("--in-place & --template cannot be used at the same time")
		}
	}
	if output, _ := cmd.Flags().GetString("output"); output != "" {
		file = output
		writeToFile = true
	}
	if writeToFile && file != "-" {
		if err := ioutil.WriteFile(file, out, 0600); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println(string(out))
	}
	return nil
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
