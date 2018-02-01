package cli

import (
	"flag"
	"fmt"
	"github.com/posener/complete"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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
			"decrypt": complete.Command{
				Flags: complete.Flags{
					"--cleartext": complete.PredictNothing,
					"--in-place":  complete.PredictNothing,
					"-i":          complete.PredictNothing,
					"--keyring":   complete.PredictAnything,
					"--output":    complete.PredictFiles("*"),
					"-o":          complete.PredictFiles("*"),
					"--template":  complete.PredictAnything,
				},
				Args: limitArgsPredictor{complete.PredictFiles("*"), 2, map[string]bool{
					// should include all !PredictNothing flags (global or not)
					"--keyring":  true,
					"--output":   true,
					"-o":         true,
					"--template": true,
				}},
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
				Args: limitArgsPredictor{complete.PredictFiles("*"), 2, map[string]bool{
					// should include all !PredictNothing flags (global or not)
					"--key":     true,
					"-k":        true,
					"--keyring": true,
					"--output":  true,
					"-o":        true,
				}},
			},
			"encrypt": complete.Command{
				Flags: complete.Flags{
					"--cleartext": complete.PredictNothing,
					"--in-place":  complete.PredictNothing,
					"-i":          complete.PredictNothing,
					"--key":       complete.PredictAnything,
					"-k":          complete.PredictAnything,
					"--keyring":   complete.PredictAnything,
					"--output":    complete.PredictFiles("*"),
					"-o":          complete.PredictFiles("*"),
				},
				Args: limitArgsPredictor{complete.PredictFiles("*"), 2, map[string]bool{
					// should include all !PredictNothing flags (global or not)
					"--key":     true,
					"-k":        true,
					"--keyring": true,
					"--output":  true,
					"-o":        true,
				}},
			},
			"introspect": complete.Command{
				Flags: complete.Flags{
					"--keyring": complete.PredictAnything,
					"--output":  complete.PredictFiles("*"),
					"-o":        complete.PredictFiles("*"),
				},
				Args: limitArgsPredictor{complete.PredictFiles("*"), 2, map[string]bool{
					// should include all !PredictNothing flags (global or not)
					"--keyring": true,
					"--output":  true,
					"-o":        true,
				}},
			},
			"merge": complete.Command{
				Flags: complete.Flags{
					"--in-place": complete.PredictNothing,
					"-i":         complete.PredictNothing,
					"--keyring":  complete.PredictAnything,
					"--output":   complete.PredictFiles("*"),
					"-o":         complete.PredictFiles("*"),
				},
				Args: limitArgsPredictor{complete.PredictFiles("*"), 3, map[string]bool{
					// should include all !PredictNothing flags (global or not)
					"--keyring": true,
					"--output":  true,
					"-o":        true,
				}},
			},
			"help": complete.Command{
				Sub: complete.Commands{
					"completion": complete.Command{
						Sub: complete.Commands{
							"bash": complete.Command{},
							"zsh":  complete.Command{},
						},
					},
					"decrypt":    complete.Command{},
					"edit":       complete.Command{},
					"encrypt":    complete.Command{},
					"introspect": complete.Command{},
					"merge":      complete.Command{},
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
	run.Sub["d"] = run.Sub["decrypt"]
	run.Sub["ee"] = run.Sub["edit"]
	run.Sub["e"] = run.Sub["encrypt"]
	run.Sub["i"] = run.Sub["introspect"]
	run.Sub["m"] = run.Sub["merge"]
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
