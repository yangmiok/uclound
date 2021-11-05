package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/ufilesdk-dev/us3-qiniu-go-sdk/syncdata/operation"
)

func main() {
	conf := flag.String("c", "conf.toml", "download config")
	file := flag.String("d", "", "file name")
	localFile := flag.String("ld", "", "file save name")
	flag.Parse()
	c, err := operation.Load(*conf)
	if err != nil {
		fmt.Println(err)
		return
	}
	d := operation.NewDownloader(c)
	f, err := d.DownloadFile(*file, *localFile)
	if err != nil {
		fmt.Println(err)
	}
	n, err := f.Seek(0, io.SeekEnd)
	fmt.Println("file end", n, err)
	f.Close()
}
