package protection

import (
	"bufio"
	"context"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const corpusStride = 256

type corpusOffset struct {
	hash   string
	offset int64
}

// FileChecker retains a read-only descriptor and one offset per 256 records.
// The operator must keep the opened corpus immutable for this process lifetime.
type FileChecker struct {
	file     *os.File
	index    []corpusOffset
	size     int64
	modified time.Time
}

func NewFileChecker(path string) (*FileChecker, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrBreachUnavailable
	}
	c := &FileChecker{file: f}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrBreachUnavailable
	}
	c.size = info.Size()
	c.modified = info.ModTime()
	reader := bufio.NewReaderSize(f, 4096)
	var offset int64
	previous := ""
	n := 0
	for {
		raw, err := reader.ReadSlice('\n')
		line := string(raw)
		if len(line) > 64 {
			return nil, ErrBreachUnavailable
		}
		if len(line) > 0 {
			hash, _, e := hexCount(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), 40, false)
			if e != nil || hash <= previous {
				return nil, ErrBreachUnavailable
			}
			if n%corpusStride == 0 {
				c.index = append(c.index, corpusOffset{hash, offset})
			}
			previous = hash
			n++
			offset += int64(len(line))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrBreachUnavailable
		}
	}
	if n == 0 {
		return nil, ErrBreachUnavailable
	}
	ok = true
	return c, nil
}
func (c *FileChecker) Close() error { return c.file.Close() }
func (c *FileChecker) Check(ctx context.Context, password string) (bool, error) {
	if ctx.Err() != nil {
		return false, ErrBreachUnavailable
	}
	info, err := c.file.Stat()
	if err != nil || info.Size() != c.size || !info.ModTime().Equal(c.modified) {
		return false, ErrBreachUnavailable
	}
	hash := passwordDigest(password)
	i := sort.Search(len(c.index), func(i int) bool { return c.index[i].hash > hash }) - 1
	if i < 0 {
		return false, nil
	}
	// SectionReader uses ReadAt, so concurrent checks never share a seek cursor.
	start := c.index[i].offset
	end := c.size
	if i+1 < len(c.index) {
		end = c.index[i+1].offset
	}
	scan := bufio.NewScanner(io.NewSectionReader(c.file, start, end-start))
	scan.Buffer(make([]byte, 128), 128)
	for scan.Scan() {
		if ctx.Err() != nil {
			return false, ErrBreachUnavailable
		}
		key, _, err := hexCount(scan.Text(), 40, false)
		if err != nil {
			return false, err
		}
		if key == hash {
			return true, nil
		}
		if key > hash {
			return false, nil
		}
	}
	if scan.Err() != nil {
		return false, ErrBreachUnavailable
	}
	return false, nil
}
