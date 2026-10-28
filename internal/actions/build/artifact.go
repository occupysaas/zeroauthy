package build

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ID is the content address of a build: the SHA-256 of the runtime and the
// resolved dependencies sorted by name. Identical sets share one build.
func ID(runtime string, resolved []store.Dependency) string {
	deps := slices.Clone(resolved)
	slices.SortFunc(deps, func(a, b store.Dependency) int { return strings.Compare(a.Name, b.Name) })
	h := sha256.New()
	fmt.Fprintf(h, "zeroauthy-actions-build\x00%s\x00", runtime)
	for _, d := range deps {
		fmt.Fprintf(h, "%s@%s\x00", d.Name, d.Version)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var errTooLarge = errors.New("exceeds the artifact size limit")

// limitedBuffer fails writes past max bytes.
type limitedBuffer struct {
	bytes.Buffer
	max int64
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if int64(b.Len()+len(p)) > b.max {
		return 0, errTooLarge
	}
	return b.Buffer.Write(p)
}

// pack tars dir's node_modules tree (directories and regular files only,
// deterministic order and metadata) into at most max bytes. Links and other
// file types fail the build: the extracted tree must hold nothing else.
func pack(dir string, max int64) ([]byte, error) {
	out := &limitedBuffer{max: max}
	tw := tar.NewWriter(out)
	modules := filepath.Join(dir, "node_modules")
	if _, err := os.Lstat(modules); errors.Is(err, fs.ErrNotExist) {
		if err := tw.Close(); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	}
	err := filepath.WalkDir(modules, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		switch {
		case d.Type().IsDir():
			return tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700, Format: tar.FormatPAX})
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			if info.Size() > max {
				return errTooLarge
			}
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: info.Size(), Format: tar.FormatPAX}); err != nil {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.CopyN(tw, f, info.Size())
			return err
		default:
			return fmt.Errorf("installed tree has a link or special file %s", name)
		}
	})
	if err == nil {
		err = tw.Close()
	}
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// extract writes a packed artifact into dst, an empty directory, refusing
// any entry that is not a directory or regular file or that names a path
// outside dst. Directories are 0700 and files 0600; at most max bytes of
// file content are written.
func extract(art []byte, dst string, max int64) error {
	tr := tar.NewReader(bytes.NewReader(art))
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name, err := entryPath(hdr.Name)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 || total+hdr.Size > max {
				return errTooLarge
			}
			total += hdr.Size
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			_, err = io.CopyN(f, tr, hdr.Size)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("entry %q has unsupported type %q", hdr.Name, hdr.Typeflag)
		}
	}
}

// entryPath returns name as a clean relative slash path inside the root, or
// an error for absolute paths and any ".." component.
func entryPath(name string) (string, error) {
	n := strings.TrimSuffix(name, "/")
	if n == "" || strings.HasPrefix(n, "/") || strings.Contains(n, "\\") || filepath.IsAbs(n) {
		return "", fmt.Errorf("entry %q is not a relative path", name)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." || part == "." || part == "" {
			return "", fmt.Errorf("entry %q escapes the build root", name)
		}
	}
	if path.Clean(n) != n || (n != "node_modules" && !strings.HasPrefix(n, "node_modules/")) {
		return "", fmt.Errorf("entry %q is outside node_modules", name)
	}
	return n, nil
}
