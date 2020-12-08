package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shyiko/complete"
)

func init() {
	complete.LastArgBreaks = `"'@><=;|&(:`
}

type Completion struct{}

func (c *Completion) GenBashCompletion(w io.Writer) error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "complete -C %s %s\n", bin, filepath.Base(bin))
	return nil
}

func (c *Completion) GenZshCompletion(w io.Writer) error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "autoload +X compinit && compinit\nautoload +X bashcompinit && bashcompinit\ncomplete -C %s %s\n",
		bin, filepath.Base(bin))
	return nil
}

type limitArgsPredictor struct {
	Predictor           complete.Predictor
	Limit               int
	FlagsExpectingValue map[string]bool
}

func (p limitArgsPredictor) Predict(args complete.Args) []string {
	c := p.Limit
	for i, arg := range args.Completed {
		if !strings.HasPrefix(arg, "-") && (i == 0 || !p.FlagsExpectingValue[args.Completed[i-1]]) {
			c--
		}
		if c == 0 {
			return nil
		}
	}
	return p.Predictor.Predict(args)
}

func (c *Completion) Execute() (bool, error) {
	bin, err := os.Executable()
	if err != nil {
		return false, err
	}
	run := complete.Command{
		Sub: complete.Commands{
			"completion": complete.Command{
				Sub: complete.Commands{
					"bash": complete.Command{},
					"zsh":  complete.Command{},
				},
			},
			"create": complete.Command{
				Flags: complete.Flags{
					"--annotation":  complete.PredictAnything,
					"-a":            complete.PredictAnything,
					"--data":        complete.PredictAnything,
					"-d":            complete.PredictAnything,
					"--string-data": complete.PredictAnything,
					"-s":            complete.PredictAnything,
					"--force":       complete.PredictNothing,
					"-f":            complete.PredictNothing,
					/*
						"--from-file":    complete.PredictFiles("*"),
						"--from-literal": complete.PredictAnything,
					*/
					"--key":      complete.PredictAnything,
					"-k":         complete.PredictAnything,
					"--keyring":  complete.PredictAnything,
					"--label":    complete.PredictAnything,
					"-l":         complete.PredictAnything,
					"--metadata": complete.PredictAnything,
					"-m":         complete.PredictAnything,
					"--output":   complete.PredictFiles("*"),
					"-o":         complete.PredictFiles("*"),
					"--parent":   complete.PredictFiles("*"),
					"-p":         complete.PredictFiles("*"),
				},
				Args: complete.PredictFiles("*"),
			},
			"decrypt": complete.Command{
				Flags: complete.Flags{
					"--cleartext": complete.PredictNothing,
					"-x":          complete.PredictNothing,
					"--in-place":  complete.PredictNothing,
					"-i":          complete.PredictNothing,
					"--keyring":   complete.PredictAnything,
					"--output":    complete.PredictFiles("*"),
					"-o":          complete.PredictFiles("*"),
					"--template":  complete.PredictAnything,
				},
				Args: complete.PredictFiles("*"),
			},
			"edit": complete.Command{
				Flags: complete.Flags{
					"--base64":        complete.PredictNothing,
					"-b":              complete.PredictNothing,
					"--force":         complete.PredictNothing,
					"-f":              complete.PredictNothing,
					"--in-place":      complete.PredictNothing,
					"-i":              complete.PredictNothing,
					"--key":           complete.PredictAnything,
					"-k":              complete.PredictAnything,
					"--keyring":       complete.PredictAnything,
					"--output":        complete.PredictFiles("*"),
					"-o":              complete.PredictFiles("*"),
					"--recompute-mac": complete.PredictNothing,
					"--rotate":        complete.PredictNothing,
					"-r":              complete.PredictNothing,
				},
				Args: complete.PredictFiles("*"),
			},
			"encrypt": complete.Command{
				Flags: complete.Flags{
					"--cleartext": complete.PredictNothing,
					"-x":          complete.PredictNothing,
					"--in-place":  complete.PredictNothing,
					"-i":          complete.PredictNothing,
					"--key":       complete.PredictAnything,
					"-k":          complete.PredictAnything,
					"--keyring":   complete.PredictAnything,
					"--output":    complete.PredictFiles("*"),
					"-o":          complete.PredictFiles("*"),
				},
				Args: complete.PredictFiles("*"),
			},
			"introspect": complete.Command{
				Flags: complete.Flags{
					"--keyring": complete.PredictAnything,
					"--output":  complete.PredictFiles("*"),
					"-o":        complete.PredictFiles("*"),
				},
				Args: complete.PredictFiles("*"),
			},
			"patch": complete.Command{
				Flags: complete.Flags{
					"--annotation":  complete.PredictAnything,
					"-a":            complete.PredictAnything,
					"--data":        complete.PredictAnything,
					"-d":            complete.PredictAnything,
					"--string-data": complete.PredictAnything,
					"-s":            complete.PredictAnything,
					/*
						"--from-file":    complete.PredictFiles("*"),
						"--from-literal": complete.PredictAnything,
					*/
					"--in-place": complete.PredictNothing,
					"-i":         complete.PredictNothing,
					"--key":      complete.PredictAnything,
					"-k":         complete.PredictAnything,
					"--keyring":  complete.PredictAnything,
					"--label":    complete.PredictAnything,
					"-l":         complete.PredictAnything,
					"--metadata": complete.PredictAnything,
					"-m":         complete.PredictAnything,
					"--output":   complete.PredictFiles("*"),
					"-o":         complete.PredictFiles("*"),
					"--rotate":   complete.PredictAnything,
					"-r":         complete.PredictAnything,
				},
				Args: complete.PredictFiles("*"),
			},
			"help": complete.Command{
				Sub: complete.Commands{
					"completion": complete.Command{
						Sub: complete.Commands{
							"bash": complete.Command{},
							"zsh":  complete.Command{},
						},
					},
					"create":     complete.Command{},
					"decrypt":    complete.Command{},
					"edit":       complete.Command{},
					"encrypt":    complete.Command{},
					"introspect": complete.Command{},
					"patch":      complete.Command{},
				},
			},
		},
		Flags: complete.Flags{
			"--version": complete.PredictNothing,
		},
		GlobalFlags: complete.Flags{
			"--debug": complete.PredictNothing,
			"--help":  complete.PredictNothing,
			"-h":      complete.PredictNothing,
		},
	}
	limitArgsPredictor := func(cmd string, limit int) {
		c := run.Sub[cmd]
		m := make(map[string]bool)
		for key, predictor := range c.Flags {
			if predictor != nil {
				m[key] = true
			}
		}
		c.Args = limitArgsPredictor{c.Args, limit + 1, m}
		run.Sub[cmd] = c
	}
	for cmd, limit := range map[string]int{
		"create":     1,
		"decrypt":    1,
		"edit":       1,
		"encrypt":    1,
		"introspect": 1,
		"patch":      1,
	} {
		limitArgsPredictor(cmd, limit)
	}
	for alias, cmd := range map[string]string{
		"c":  "create",
		"d":  "decrypt",
		"ee": "edit",
		"e":  "encrypt",
		"i":  "introspect",
		"p":  "patch",
	} {
		run.Sub[alias] = run.Sub[cmd]
	}
	completion := complete.New(filepath.Base(bin), run)
	if os.Getenv("COMP_LINE") != "" {
		flag.Parse()
		completion.Complete()
		return true, nil
	}
	return false, nil
}

func NewCompletion() *Completion {
	return &Completion{}
}
