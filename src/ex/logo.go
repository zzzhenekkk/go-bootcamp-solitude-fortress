package ex

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
)

func main() {
	width, height := 300, 300
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Пример простого рисунка: фон голубой, красный круг в центре
	blue := color.RGBA{0, 0, 255, 255}
	red := color.RGBA{255, 0, 0, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{blue}, image.Point{}, draw.Src)

	centerX, centerY := width/2, height/2
	radius := 100
	for x := centerX - radius; x <= centerX+radius; x++ {
		for y := centerY - radius; y <= centerY+radius; y++ {
			if (x-centerX)*(x-centerX)+(y-centerY)*(y-centerY) <= radius*radius {
				img.Set(x, y, red)
			}
		}
	}

	file, err := os.Create("amazing_logo.png")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	png.Encode(file, img)
}
