from PIL import Image

# Open multi-frame TIFF
tiff_image = Image.open("data/sample_fingerprints/C.tif")

# Loop through all pages
for i in range(tiff_image.n_frames):
    tiff_image.seek(i)  # Move to next frame
    tiff_image.save(f"data/sample_fingerprints/page_C{i}.png")  # Save as PNG

print("Saved all TIFF pages as PNG files.")
