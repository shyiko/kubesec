package cmd

import (
	"bytes"
	"errors"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"unicode"
)

func Edit(content []byte) ([]byte, error) {
	input, ctx, err := Decrypt(content)
	if err != nil {
		return nil, err
	}
	tmp, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, err
	}
	defer func() { os.Remove(tmp.Name()) }()
	ioutil.WriteFile(tmp.Name(), input, 0600)
	openInEditor(tmp.Name())
	output, err := ioutil.ReadFile(tmp.Name())
	if err != nil {
		return nil, err
	}
	if bytes.Equal(input, output) {
		return content, nil
	}
	return Encrypt(output, *ctx)
}

func openInEditor(path string) error {
	editor := os.Getenv("EDITOR")
	var cmd *exec.Cmd
	var args []string
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
	cmd.Stdout = os.Stdout
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
