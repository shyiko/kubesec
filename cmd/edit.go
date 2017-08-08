package cmd

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
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
	if editor == "" {
		cmd = exec.Command("which", "vim") // todo: vim -n -i NONE -u NONE
		out, err := cmd.Output()
		if err != nil {
			return errors.New("$EDITOR not defined")
		}
		cmd = exec.Command(strings.Split(string(out), "\n")[0], path)
	} else {
		cmd = exec.Command(editor, path)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
