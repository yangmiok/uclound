package sectorstorage

import (
	"crypto/rand"
	"errors"
	"fmt"
	ffi "github.com/filecoin-project/filecoin-ffi"
	"github.com/filecoin-project/specs-actors/actors/runtime/proof"
	"github.com/ipfs/go-cid"
	"os"
	"path/filepath"
	"strconv"

	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/lotus/extern/sector-storage/storiface"

	"github.com/ufilesdk-dev/us3-qiniu-go-sdk/syncdata/operation"
)

type SectorFile struct {
	Sid  abi.SectorID `json:"sid"`
	Size int64        `json:"size"`
}

func CheckSectors(root string, sectors []abi.SectorID, size int64, cids []cid.Cid) []abi.SectorID {
	proofType := getProofType(size)
	proofType.RegisteredWindowPoStProof()
	proofType.RegisteredWinningPoStProof()
	ssize, _ := proofType.SectorSize()
	var bad = make(map[abi.SectorID]string)
	var checkList = make(map[string]SectorFile, len(sectors)*2)
	for _, v := range sectors {
		sealedPath := filepath.Join(root, storiface.FTCache.String(), storiface.SectorName(v))
		cachePath := filepath.Join(root, storiface.FTSealed.String(), storiface.SectorName(v))
		addCheckList(storiface.SectorPaths{
			ID:     v,
			Cache:  sealedPath,
			Sealed: cachePath,
		}, v, ssize, checkList)
	}

	checkBad(bad, checkList)
	if len(cids) != 0 {
		for i, v := range sectors {
			sealedPath := filepath.Join(root, storiface.FTSealed.String(), storiface.SectorName(v))
			cachePath := filepath.Join(root, storiface.FTCache.String(), storiface.SectorName(v))
			if _, ok := bad[v]; !ok {
				d, _ := checkProof(v, proofType, cids[i], cachePath, sealedPath)
				if d != nil {
					bad[v] = *d
				}
			}
		}
	}
	keys := make([]abi.SectorID, 0, len(bad))
	for k := range bad {
		keys = append(keys, k)
	}
	return keys
}

func addCheckList(lp storiface.SectorPaths, sid abi.SectorID, ssize abi.SectorSize, checkList map[string]SectorFile) {
	checkList[lp.Sealed] = SectorFile{
		Sid:  sid,
		Size: int64(ssize),
	}
	checkList[filepath.Join(lp.Cache, "t_aux")] = SectorFile{
		Sid:  sid,
		Size: 0,
	}
	checkList[filepath.Join(lp.Cache, "p_aux")] = SectorFile{
		Sid:  sid,
		Size: 0,
	}

	addCacheFilePathsForSectorSize(checkList, lp.Cache, ssize, sid)
}

func fileCount(ssize abi.SectorSize) int {
	c := 3
	switch ssize {
	case 2 << 10:
		fallthrough
	case 8 << 20:
		fallthrough
	case 512 << 20:
		c += 1
	case 32 << 30:
		c += 8
	case 64 << 30:
		c += 16
	default:
		log.Warnf("not checking cache files of %s sectors for faults", ssize)
	}
	return c
}

func insert(bad map[abi.SectorID]string, sid abi.SectorID, reason string) {
	for k, _ := range bad {
		if k.Miner == sid.Miner && k.Number == sid.Number {
			return
		}
	}
	bad[sid] = reason
}

func checkBad(bad map[abi.SectorID]string, checkList map[string]SectorFile) error {
	list := getKeys(checkList)
	if len(list) == 0 {
		return nil
	}
	conf_file := os.Getenv("US3")
	if conf_file == "" {
		return nil
	}
	conf, err := operation.Load(conf_file)
	if err != nil {
		log.Error("load conf failed", conf_file, err)
		return err
	}
	if conf.Sim {
		return nil
	}
	lister := operation.NewListerV2()
	fList := lister.ListStat(list)
	if fList == nil {
		return errors.New("list stats failed")
	}
	for _, v := range fList {
		//log.Info("file in list", v.Name, v.Size)
		p, ok := checkList["/"+v.Name]
		if !ok {
			fmt.Println("no file!!!", "/"+v.Name)
			continue
		}

		if v.Size == -1 { // not found
			fmt.Println("file is not exist", "/"+v.Name, p.Sid.Number, p.Sid.Miner)
			insert(bad, p.Sid, "file is not exist "+v.Name)
		} else if p.Size != 0 && p.Size != v.Size {
			fmt.Println(p.Size, v.Size)
			fmt.Println("file size is wrong", p.Size, v.Size, "/"+v.Name, p.Sid.Number, p.Sid.Miner)
			insert(bad, p.Sid, "file size is wrong "+v.Name+"-"+strconv.FormatInt(v.Size, 10))
		}
	}
	return nil
}

func addCacheFilePathsForSectorSize(checkList map[string]SectorFile, cacheDir string, ssize abi.SectorSize, sid abi.SectorID) {
	switch ssize {
	case 2 << 10:
		fallthrough
	case 8 << 20:
		fallthrough
	case 512 << 20:
		checkList[filepath.Join(cacheDir, "sc-02-data-tree-r-last.dat")] = SectorFile{
			Sid:  sid,
			Size: 0,
		}
	case 32 << 30:
		for i := 0; i < 8; i++ {
			checkList[filepath.Join(cacheDir, fmt.Sprintf("sc-02-data-tree-r-last-%d.dat", i))] = SectorFile{
				Sid:  sid,
				Size: 0,
			}
		}
	case 64 << 30:
		for i := 0; i < 16; i++ {
			checkList[filepath.Join(cacheDir, fmt.Sprintf("sc-02-data-tree-r-last-%d.dat", i))] = SectorFile{
				Sid:  sid,
				Size: 0,
			}
		}
	default:
		log.Warnf("not checking cache files of %s sectors for faults", ssize)
	}
}

func getKeys(m map[string]SectorFile) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k[1:])
	}
	return keys
}

func checkProof(sectorId abi.SectorID, proofType abi.RegisteredSealProof, commr cid.Cid, cachePath, sealedPath string) (desc *string, err error) {
	wpp, err := proofType.RegisteredWindowPoStProof()
	if err != nil {
		return nil, err
	}

	var pr abi.PoStRandomness = make([]byte, abi.RandomnessLength)
	_, _ = rand.Read(pr)
	pr[31] &= 0x3f

	ch, err := ffi.GeneratePoStFallbackSectorChallenges(wpp, sectorId.Miner, pr, []abi.SectorNumber{
		sectorId.Number,
	})
	if err != nil {
		log.Warnw("CheckProvable Sector FAULT: generating challenges", "sector", sectorId, "sealed", sealedPath, "cache", cachePath, "err", err)
		d := fmt.Sprintf("generating fallback challenges: %s", err)
		return &d, nil
	}

	_, err = ffi.GenerateSingleVanillaProof(ffi.PrivateSectorInfo{
		SectorInfo: proof.SectorInfo{
			SealProof:    proofType,
			SectorNumber: sectorId.Number,
			SealedCID:    commr,
		},
		CacheDirPath:     cachePath,
		PoStProofType:    wpp,
		SealedSectorPath: sealedPath,
	}, ch.Challenges[sectorId.Number])
	if err != nil {
		log.Warnw("CheckProvable Sector FAULT: generating vanilla proof", "sector", sectorId,
			"sealed", sealedPath, "cache", cachePath, "err", err)
		d := fmt.Sprintf("generating vanilla proof: %s", err)
		return &d, nil
	}
	return nil, nil
}

func getProofType(size int64) abi.RegisteredSealProof {
	switch size {
	case 2 << 10:
		return abi.RegisteredSealProof_StackedDrg2KiBV1_1
	case 512 << 20:
		return abi.RegisteredSealProof_StackedDrg512MiBV1_1
	case 32 << 30:
		return abi.RegisteredSealProof_StackedDrg32GiBV1_1
	}
	return abi.RegisteredSealProof_StackedDrg32GiBV1_1
}
