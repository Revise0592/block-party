package servers

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif" // decoders for SetIcon
	_ "image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
)

// The server picture. Java servers show server-icon.png (64 by 64 pixels,
// in the server's folder) next to the server in the multiplayer list, read
// when the server starts. Bedrock and Hytale servers don't have a picture of
// their own, so for them it only shows in the panel. Any picture is cropped
// to a square from its middle and resized, so a photo from a phone works.

const (
	iconFile = "server-icon.png"
	iconSize = 64
	// MaxIconUpload is the biggest picture file the panel takes.
	MaxIconUpload = 15 << 20
	maxIconPixels = 50_000_000 // larger pictures would take a lot of memory to open
)

var errIconFormat = errors.New("that isn't a picture the panel can read; use a PNG, JPG or GIF")

func (s *Server) iconPath() string { return filepath.Join(s.dir(), iconFile) }

// iconStamp is when the picture last changed (Unix milliseconds), or 0 when
// there isn't one. The page adds it to the picture's address so a new
// picture shows straight away.
func (s *Server) iconStamp() int64 {
	fi, err := os.Stat(s.iconPath())
	if err != nil || !fi.Mode().IsRegular() {
		return 0
	}
	return fi.ModTime().UnixMilli()
}

// Icon returns the server's picture (a PNG), or os.ErrNotExist.
func (s *Server) Icon() ([]byte, error) {
	f, err := os.Open(s.iconPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxIconUpload))
}

// SetIcon makes a picture the server's picture.
func (s *Server) SetIcon(data []byte) error {
	b, err := makeIcon(data)
	if err != nil {
		return err
	}
	path := s.iconPath()
	if err := os.WriteFile(path+".tmp", b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		os.Remove(path + ".tmp")
		return err
	}
	return nil
}

// RemoveIcon removes the server's picture (Java shows its default one).
func (s *Server) RemoveIcon() error {
	if err := os.Remove(s.iconPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// makeIcon turns a picture into a 64 by 64 PNG.
func makeIcon(data []byte) ([]byte, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, errIconFormat
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > maxIconPixels {
		return nil, errors.New("that picture is too big to open; try a smaller one")
	}
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, errIconFormat
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, squareIcon(src)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// squareIcon crops the middle square of a picture and resizes it to
// iconSize. Each new pixel is the average of the pixels it covers, which
// keeps shrunk photos smooth; a picture smaller than the icon is enlarged
// without blurring, which suits pixel art.
func squareIcon(src image.Image) *image.RGBA {
	b := src.Bounds()
	side := min(b.Dx(), b.Dy())
	x0, y0 := b.Min.X+(b.Dx()-side)/2, b.Min.Y+(b.Dy()-side)/2
	rgba := image.NewRGBA(image.Rect(0, 0, side, side))
	draw.Draw(rgba, rgba.Bounds(), src, image.Pt(x0, y0), draw.Src)
	out := image.NewRGBA(image.Rect(0, 0, iconSize, iconSize))
	span := func(i int) (int, int) {
		a, z := i*side/iconSize, (i+1)*side/iconSize
		return a, max(z, a+1)
	}
	for oy := range iconSize {
		ya, yz := span(oy)
		for ox := range iconSize {
			xa, xz := span(ox)
			var r, g, bl, a, n uint64
			for y := ya; y < yz; y++ {
				row := rgba.Pix[y*rgba.Stride:]
				for x := xa; x < xz; x++ {
					p := row[x*4 : x*4+4]
					r, g, bl, a = r+uint64(p[0]), g+uint64(p[1]), bl+uint64(p[2]), a+uint64(p[3])
					n++
				}
			}
			out.SetRGBA(ox, oy, color.RGBA{uint8(r / n), uint8(g / n), uint8(bl / n), uint8(a / n)})
		}
	}
	return out
}
