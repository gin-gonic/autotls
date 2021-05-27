package autotls

import (
	"errors"
	"golang.org/x/crypto/acme/autocert"
	"os"
	"path/filepath"
	"runtime"
)

func getCacheDir() (autocert.DirCache, error) {
	dir := cacheDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", errors.New("warning: autocert.NewListener not using a cache: " + err.Error())
	}
	return autocert.DirCache(dir), nil
}

func cacheDir() string {
	const base = "golang-autocert"
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(homeDir(), "Library", "Caches", base)
	case "windows":
		for _, ev := range []string{"APPDATA", "CSIDL_APPDATA", "TEMP", "TMP"} {
			if v := os.Getenv(ev); v != "" {
				return filepath.Join(v, base)
			}
		}
		// Worst case:
		return filepath.Join(homeDir(), base)
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, base)
	}
	return filepath.Join(homeDir(), ".cache", base)
}

func homeDir() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/"
}
