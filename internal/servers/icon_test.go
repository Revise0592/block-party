package servers

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"testing"
)

func TestSetIconCropsAndResizes(t *testing.T) {
	_, s := newSettingsServer(t)
	if s.Status().Icon != 0 {
		t.Fatal("a new server shouldn't have a picture")
	}
	// A wide photo: red on the left and right, blue in the middle square.
	src := image.NewRGBA(image.Rect(0, 0, 300, 200))
	for y := range 200 {
		for x := range 300 {
			c := color.RGBA{255, 0, 0, 255}
			if x >= 50 && x < 250 {
				c = color.RGBA{0, 0, 255, 255}
			}
			src.Set(x, y, c)
		}
	}
	var in bytes.Buffer
	jpeg.Encode(&in, src, &jpeg.Options{Quality: 95})
	if err := s.SetIcon(in.Bytes()); err != nil {
		t.Fatal(err)
	}
	b, err := s.Icon()
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 64 || img.Bounds().Dy() != 64 {
		t.Fatalf("size %v, want 64x64", img.Bounds())
	}
	for _, p := range []image.Point{{0, 0}, {63, 63}, {32, 32}} {
		r, _, bl, _ := img.At(p.X, p.Y).RGBA()
		if r > 0x2000 || bl < 0xe000 {
			t.Errorf("pixel %v isn't from the middle of the picture: r=%x b=%x", p, r, bl)
		}
	}
	if s.Status().Icon == 0 {
		t.Error("Status doesn't show the picture")
	}
	if err := s.RemoveIcon(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.iconPath()); !os.IsNotExist(err) || s.Status().Icon != 0 {
		t.Error("the picture is still there")
	}
	if err := s.RemoveIcon(); err != nil {
		t.Errorf("removing it twice: %v", err)
	}
}

func TestSetIconSmallPictureAndBadFiles(t *testing.T) {
	_, s := newSettingsServer(t)
	// A 2 by 2 pixel-art picture is enlarged without blurring.
	src := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	src.Set(0, 0, color.NRGBA{255, 255, 255, 255})
	src.Set(1, 1, color.NRGBA{255, 255, 255, 255})
	var in bytes.Buffer
	png.Encode(&in, src)
	if err := s.SetIcon(in.Bytes()); err != nil {
		t.Fatal(err)
	}
	b, _ := s.Icon()
	img, _ := png.Decode(bytes.NewReader(b))
	if _, _, _, a := img.At(31, 0).RGBA(); a != 0xffff {
		t.Errorf("top left should be solid white, alpha %x", a)
	}
	if _, _, _, a := img.At(32, 0).RGBA(); a != 0 {
		t.Errorf("top right should be see-through, alpha %x", a)
	}
	for _, bad := range [][]byte{nil, []byte("not a picture"), []byte("\x89PNG\r\n\x1a\n broken")} {
		if err := s.SetIcon(bad); err == nil {
			t.Errorf("%q was taken as a picture", bad)
		}
	}
	got, _ := s.Icon()
	if !bytes.Equal(got, b) {
		t.Error("a bad upload changed the picture")
	}
}
