package main

import (
	"encoding/csv"
	"flag"
	"github.com/docker/go-units"
	"log"
	"os"
	"strconv"

	"github.com/filecoin-project/go-state-types/abi"
	sectorstorage "github.com/filecoin-project/lotus/extern/sector-storage"
	"github.com/ipfs/go-cid"
)

func main() {
	c := flag.String("d", "list.tsv", "sector id list")
	miner := flag.Uint64("m", 123, "miner id 123")
	root := flag.String("p", "/home/fc", "prefix path")
	sizeStr := flag.String("s", "32GiB", "sector size")
	flag.Parse()
	sectorSizeInt, err := units.RAMInBytes(*sizeStr)
	if err != nil {
		log.Println(err)
		return
	}
	sectors, cids := loadSectors(*c)
	var sids []abi.SectorID
	for _, v := range sectors {
		sid := abi.SectorID{
			Miner:  abi.ActorID(*miner),
			Number: v,
		}
		sids = append(sids, sid)
	}

	bad := sectorstorage.CheckSectors(*root, sids, sectorSizeInt, cids)
	if len(bad) != 0 {
		for _, v := range bad {
			log.Println("sector is not exist", v.Miner, v.Number)
		}
	}
}

func loadSectors(file string) (ret []abi.SectorNumber, cids []cid.Cid) {
	f, err := os.Open(file)
	if err != nil {
		log.Println(err)
		return nil, nil
	}
	l, err := csv.NewReader(f).ReadAll()
	if err != nil {
		log.Println(err)
		return nil, nil
	}

	for i, v := range l {
		n, err := strconv.ParseUint(v[0], 10, 64)
		if err != nil {
			log.Println(err, v[0], i)
			return nil, nil
		}
		ret = append(ret, abi.SectorNumber(n))
		if len(v) == 2 {
			c, err := cid.Decode(v[1])
			if err != nil {
				log.Println(err, v[1], i)
				return nil, nil
			}
			cids = append(cids, c)
		}
	}
	return
}
