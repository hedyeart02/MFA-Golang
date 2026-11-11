package public

import (
	"embed"
	"io/fs"
)

//go:embed assets
var assetFiles embed.FS

// AssetsFS returns the embedded public assets filesystem rooted at assets/.
func AssetsFS() (fs.FS, error) {
	return fs.Sub(assetFiles, "assets")
}

