package policy

import (
	"os"
)

// fileStat is the production file-stat implementation used by the
// hot-reload mtime tracker. It is a package-level var so tests can
// inject fake filesystem metadata without touching disk.
var fileStat = func(path string) (fileInfo, error) {
	return os.Stat(path)
}
