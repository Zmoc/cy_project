import numpy as np
import matplotlib.pyplot as plt
from skimage.feature import corner_harris, corner_peaks
from skimage.morphology import skeletonize
from skimage.color import rgb2gray
from skimage.io import imread

from skimage.filters import threshold_otsu

# Compute an optimal threshold using Otsu’s method


# Load a fingerprint image (convert to grayscale if needed)
image = imread('data/sample_fingerprints/A.png', as_gray=True)  # Replace with your image

# Convert to binary (assuming the image has a clear foreground/background)
thresh = threshold_otsu(image)

# Convert to binary using the computed threshold
binary_image = image < thresh  # Use '>' if ridges are white

# Skeletonize the fingerprint
skeleton = skeletonize(binary_image)

# Detect minutiae points using Harris corner detection
corners = corner_harris(skeleton)
minutiae_points = corner_peaks(corners, min_distance=5)

fig, axes = plt.subplots(1, 3, figsize=(15, 5))

axes[0].imshow(image, cmap='gray')
axes[0].set_title("Original Image")

axes[1].imshow(binary_image, cmap='gray')
axes[1].set_title("Binary Image")

axes[2].imshow(skeleton, cmap='gray')
axes[2].scatter(minutiae_points[:, 1], minutiae_points[:, 0], c='red', s=15, label="Minutiae")
axes[2].set_title("Skeleton + Minutiae")
axes[2].legend()

plt.show()
