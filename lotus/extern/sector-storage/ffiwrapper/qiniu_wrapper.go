package ffiwrapper

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/filecoin-project/specs-storage/storage"
	"github.com/ufilesdk-dev/us3-qiniu-go-sdk/syncdata/operation"
	"golang.org/x/xerrors"

	rlepluslazy "github.com/filecoin-project/go-bitfield/rle"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/lotus/extern/sector-storage/fr32"
	"github.com/filecoin-project/lotus/extern/sector-storage/partialfile"
	"github.com/filecoin-project/lotus/extern/sector-storage/storiface"
)

func trailer(downloader *operation.Downloader, p string, maxPieceSize int64) (*rlepluslazy.RLE, error) {
	size, data, err := downloader.DownloadRangeBytes(p, -1, 4)
	if err != nil {
		return nil, err
	}

	if size < int64(maxPieceSize) {
		return nil, xerrors.Errorf("sector file '%s' was smaller than the sector size %d < %d", p, size, maxPieceSize)
	}

	var rle rlepluslazy.RLE
	err = func() error {
		// read trailer
		var tlen [4]byte
		copy(tlen[:], data)

		// sanity-check the length
		trailerLen := binary.LittleEndian.Uint32(tlen[:])
		expectLen := int64(trailerLen) + int64(len(tlen)) + int64(maxPieceSize)
		if expectLen != size {
			return xerrors.Errorf("file '%s' has inconsistent length; has %d bytes; expected %d (%d trailer, %d sector data)", p, size, expectLen, int64(trailerLen)+int64(len(tlen)), maxPieceSize)
		}
		if trailerLen > partialfile.VeryLargeRle {
			log.Warnf("Partial file '%s' has a VERY large trailer with %d bytes", p, trailerLen)
		}

		trailerStart := size - int64(len(tlen)) - int64(trailerLen)
		if trailerStart != int64(maxPieceSize) {
			return xerrors.Errorf("expected sector size to equal trailer start index")
		}

		_, trailerBytes, err := downloader.DownloadRangeBytes(p, trailerStart, int64(trailerLen))
		if err != nil {
			return xerrors.Errorf("reading trailer: %w", err)
		}

		rle, err = rlepluslazy.FromBuf(trailerBytes)
		if err != nil {
			return xerrors.Errorf("decoding trailer: %w", err)
		}

		it, err := rle.RunIterator()
		if err != nil {
			return xerrors.Errorf("getting trailer run iterator: %w", err)
		}

		f, err := rlepluslazy.Fill(it)
		if err != nil {
			return xerrors.Errorf("filling bitfield: %w", err)
		}
		lastSet, err := rlepluslazy.Count(f)
		if err != nil {
			return xerrors.Errorf("finding last set byte index: %w", err)
		}

		if lastSet > uint64(maxPieceSize) {
			return xerrors.Errorf("last set byte at index higher than sector size: %d > %d", lastSet, maxPieceSize)
		}
		return nil
	}()
	return &rle, err
}

func (sb *Sealer) ReadPieceQiniu(ctx context.Context, writer io.Writer, sector storage.SectorRef,
	offset storiface.UnpaddedByteIndex, size abi.UnpaddedPieceSize) (bool, error) {
	p, done, err := sb.sectors.AcquireSector(ctx, sector, storiface.FTUnsealed, storiface.FTNone, storiface.PathStorage)
	if err != nil {
		return false, xerrors.Errorf("acquire unsealed sector path: %w", err)
	}
	defer done()

	ssize, err := sector.ProofType.SectorSize()
	if err != nil {
		return false, err
	}

	maxPieceSize := abi.PaddedPieceSize(ssize)

	downloader := operation.NewDownloaderV2()

	rle, err := trailer(downloader, p.Unsealed, int64(maxPieceSize))
	if err != nil {
		return false, err
	}

	pf := partialfile.NewPartialFile(
		maxPieceSize,
		p.Unsealed,
		*rle,
	)

	_, err = pf.HasAllocated(offset, size)
	if err != nil {
		return false, err
	}

	//--
	offset2 := offset.Padded()
	size2 := size.Padded()

	{
		have, err := pf.Allocated()
		if err != nil {
			return false, err
		}

		and, err := rlepluslazy.And(have, partialfile.PieceRun(offset2, size2))
		if err != nil {
			return false, err
		}

		c, err := rlepluslazy.Count(and)
		if err != nil {
			return false, err
		}

		if c != uint64(size2) {
			log.Warnf("getting partial file reader reading %d unallocated bytes", uint64(size2)-c)
		}
	}

	upr, err := fr32.NewUnpadReaderV2(size.Padded(), downloader, int64(offset2), p.Unsealed)
	if err != nil {
		return false, xerrors.Errorf("creating unpadded reader: %w", err)
	}

	if _, err := io.CopyN(writer, upr, int64(size)); err != nil {
		_ = pf.Close()
		return false, xerrors.Errorf("reading unsealed file: %w", err)
	}

	if pf.NonFile() {
		return true, nil
	}

	if err := pf.Close(); err != nil {
		return false, xerrors.Errorf("closing partial file: %w", err)
	}

	return true, nil
}
