package main

import (
	"PEi/CertificateBypass"
	"PEi/Tools"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

func main() {
	Execute()
}

var (
	filename  string
	outname   string
	shellcode string
	hashcode  string
	xorcode   string
)

func Execute() {
	app := &cli.App{
		Name:      "PEi",
		Usage:     "进行PE文件的操作",
		UsageText: "[No Usage]",
		Version:   "0.1.1",
		Compiled:  time.Now(),
		Authors: []*cli.Author{
			{
				Name:  "Lings",
				Email: "lingsaa@outlook.com",
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "CertificateBypass",
				Aliases: []string{"c"},
				Usage:   "数字签名文件隐写",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filename", Aliases: []string{"f"}, Destination: &filename, Value: "", Usage: "输入文件"},
					&cli.StringFlag{Name: "outname", Aliases: []string{"o"}, Destination: &outname, Value: "", Usage: "输出文件"},
					&cli.StringFlag{Name: "shellcode", Aliases: []string{"s"}, Destination: &shellcode, Value: "", Usage: "shellcode文件"},
					&cli.StringFlag{Name: "hashcode", Aliases: []string{"c"}, Destination: &hashcode, Value: "", Usage: "16进制标识符 - String"},
				},
				Action: func(c *cli.Context) error {
					if filename == "" || outname == "" || shellcode == "" {
						return fmt.Errorf("参数输入不正确")
					}
					bytes, err := hex.DecodeString(hashcode)
					if err != nil {
						return err
					}
					CertificateBypass.Run(filename, outname, shellcode, bytes)
					return nil
				},
			},
			{
				Name:    "ShellCodeBypass",
				Aliases: []string{"s"},
				Usage:   "对ShellCode进行简单的异或求反处理(先求反再异或)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "filename", Aliases: []string{"f"}, Destination: &filename, Value: "", Usage: "shellcode文件"},
					&cli.StringFlag{Name: "outname", Aliases: []string{"o"}, Destination: &outname, Value: "", Usage: "输出文件"},
					&cli.StringFlag{Name: "xorcode", Aliases: []string{"x"}, Destination: &xorcode, Value: "", Usage: "16进制标识符 - String"},
				},
				Action: func(c *cli.Context) error {
					if filename == "" || outname == "" || xorcode == "" {
						return fmt.Errorf("参数输入不正确")
					}
					bytes, err := hex.DecodeString(xorcode)
					if err != nil {
						return err
					}
					fmt.Printf("ShellCodea将求反后异或: 0x%x\n", bytes[0])
					Tools.ShellcodePretreatment(filename, outname, bytes[0])
					return nil
				},
			},
		},

		// HideHelpCommand: true,
	}
	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}
