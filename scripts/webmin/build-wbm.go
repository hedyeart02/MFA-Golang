package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	srcDir := flag.String("src", "scripts/webmin/modules", "Source directory containing Webmin module subdirectories")
	outFile := flag.String("out", "dist/samlguard-webmin.wbm.gz", "Output .wbm.gz archive path")
	flag.Parse()

	if err := buildWBM(*srcDir, *outFile); err != nil {
		fmt.Fprintf(os.Stderr, "error building Webmin package: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Built Webmin module package: %s\n", *outFile)
}

func buildWBM(srcDir, outFile string) error {
	absSrc, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(absSrc); err != nil {
		return fmt.Errorf("source directory %q not found: %w", absSrc, err)
	}

	if err := os.MkdirAll(filepath.Dir(outFile), 0755); err != nil {
		return err
	}

	var entries []string
	err = filepath.WalkDir(absSrc, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == absSrc {
			return nil
		}
		entries = append(entries, path)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(entries)

	f, err := os.Create(outFile)
	if err != nil {
		return err
	}

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	now := time.Now().UTC()

	for _, fullPath := range entries {
		rel, err := filepath.Rel(absSrc, fullPath)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return err
		}
		tarPath := filepath.ToSlash(rel)

		info, err := os.Stat(fullPath)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return err
		}

		if info.IsDir() {
			hdr := &tar.Header{
				Name:     strings.TrimSuffix(tarPath, "/") + "/",
				Mode:     0755,
				Typeflag: tar.TypeDir,
				ModTime:  now,
				Uname:    "root",
				Gname:    "root",
				Format:   tar.FormatUSTAR,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				_ = tw.Close()
				_ = gz.Close()
				_ = f.Close()
				return err
			}
			continue
		}

		raw, err := os.ReadFile(fullPath)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return err
		}

		// Normalize CRLF -> LF for all Webmin text/script files so shebangs and configs work on Linux
		normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))

		var mode int64 = 0644
		if strings.HasSuffix(tarPath, ".cgi") || strings.HasSuffix(tarPath, ".pl") || strings.HasSuffix(tarPath, ".sh") {
			mode = 0755
		}

		hdr := &tar.Header{
			Name:     tarPath,
			Size:     int64(len(normalized)),
			Mode:     mode,
			Typeflag: tar.TypeReg,
			ModTime:  now,
			Uname:    "root",
			Gname:    "root",
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return err
		}
		if _, err := tw.Write(normalized); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			return err
		}
	}

	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = f.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
