package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"unicode"
)

type EditOpt struct {
	Base64         bool
	Rotate         bool
	KeySetMutation KeySetMutation
	Editor         string
	RecomputeMAC   bool
}

func Edit(content []byte, opt EditOpt) ([]byte, error) {
	input := content
	ctx := &EncryptionContext{}
	var rs resource
	var err error
	inputEncrypted := IsEncrypted(content)
	macValid := true
	if inputEncrypted {
		rs, ctx, err = decrypt(content, opt.RecomputeMAC)
		if err != nil {
			return nil, err
		}
		macValid = ctx.IsEmpty() || validateMAC(rs, *ctx) == nil
		if !macValid && !opt.RecomputeMAC {
			return nil, errors.New("MACs don't match.\n" +
				"Use `kubesec edit -i --recompute-mac <file>` to review & confirm content of the Secret.")
		}
		input, err = marshal(rs)
		if err != nil {
			return nil, err
		}
		if opt.Rotate {
			ctx.RotateDEK()
		}
	}
	if !opt.Base64 {
		if input, err = transform(input, decodeBase64Data); err != nil {
			return nil, err
		}
	}
	opt.KeySetMutation.applyTo(ctx)
	if !macValid {
		keys, err := listKeys(ctx)
		if err != nil {
			return nil, err
		}
		input = append([]byte(strings.Join([]string{
			"#",
			"# WARNING: MACs don't match!",
			"# (please review the content (and the keys!) before saving)",
			"#",
			"# Included key(s):",
			"#",
			"# " + strings.Join(keys, "\n# "),
			"#",
			"# (comments are automatically stripped away)",
			"#\n",
		}, "\n")), input...)
	}
	tmp, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	defer func() { os.Remove(tmp.Name()) }()
	ioutil.WriteFile(tmp.Name(), input, 0600)
	err = openInEditor(opt.Editor, tmp.Name())
	if err != nil {
		return nil, errors.New("$EDITOR (vim, if not specified) terminated with exit code other than 0")
	}
	output, err := ioutil.ReadFile(tmp.Name())
	if err != nil {
		return nil, err
	}
	if !opt.Base64 {
		if output, err = transform(output, encodeDataToBase64); err != nil {
			return nil, err
		}
	}
	return EncryptWithContext(output, *ctx)
}

func transform(data []byte, cb func(rs *resource) error) ([]byte, error) {
	rs, err := unmarshal(data)
	if err != nil {
		return nil, err
	}
	if err := cb(&rs); err != nil {
		return nil, err
	}
	return marshal(rs)
}

func listKeys(ctx *EncryptionContext) ([]string, error) {
	var res []string
	for _, keyType := range KeyTypes {
		list, err := listKeysByKeyType(ctx, keyType)
		if err != nil {
			return nil, err
		}
		var prefix string
		switch keyType {
		case KTPGP:
			prefix = "PGP: "
		case KTGCPKMS:
			prefix = "GCP KMS: "
		case KTAWSKMS:
			prefix = "AWS KMS: "
		default:
			panic(fmt.Sprintf("Unexpected Key.Type %v", keyType))
		}
		for _, value := range list {
			res = append(res, prefix+value)
		}
	}
	return res, nil
}

func decodeBase64Data(rs *resource) error {
	data := rs.data()
	for key, value := range data {
		decodedValue, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return fmt.Errorf("Failed to base64-decode %s", key)
		}
		data[key] = string(decodedValue)
	}
	return nil
}

func encodeDataToBase64(rs *resource) error {
	data := rs.data()
	for key, value := range data {
		data[key] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	return nil
}

func openInEditor(editor string, path string) error {
	var cmd *exec.Cmd
	var args []string
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		cmd = exec.Command("which", "vim")
		out, err := cmd.Output()
		if err != nil {
			return errors.New("$EDITOR not defined")
		}
		editor, args = strings.Split(string(out), "\n")[0], []string{"-n", "-i", "NONE", "-u", "NONE"}
	} else {
		editorCmd := parseCommand(editor)
		editor, args = editorCmd[0], editorCmd[1:]
	}
	args = append(args, path)
	log.Debugf(`Executing %s %s`, editor, strings.Join(args, " "))
	cmd = exec.Command(editor, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func parseCommand(command string) []string {
	var chunks []string
	i, j := 0, 0
	var r rune
	lastQuote := rune(0)
	for j, r = range command {
		switch {
		case r == lastQuote && command[j-1] != '\\':
			lastQuote = rune(0)
		case lastQuote != rune(0):
			break
		case unicode.In(r, unicode.Quotation_Mark):
			lastQuote = r
		default:
			if unicode.IsSpace(r) {
				chunks = append(chunks, unquote(command[i:j]))
				i = j + 1
			}
		}
	}
	if i <= j {
		chunks = append(chunks, unquote(command[i:j+1]))
	}
	return chunks
}

func unquote(value string) string {
	runes := []rune(value)
	if len(runes) >= 2 {
		if unicode.In(runes[0], unicode.Quotation_Mark) && runes[0] == runes[len(runes)-1] {
			value = string(runes[1 : len(runes)-1])
		}
	}
	return strings.Replace(strings.Replace(value, `\"`, `"`, -1), `\'`, `'`, -1)
}
