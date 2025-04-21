import matplotlib.pyplot as plt
from skimage.feature import corner_harris, corner_peaks
from skimage.morphology import skeletonize
import cv2


# Compute an optimal threshold using Otsu’s method
def extract_minutiae(image_path):
    img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    _, binary = cv2.threshold(img, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    skeleton = skeletonize(binary // 255)  # Convert to binary skeleton
    minutiae_points = corner_peaks(corner_harris(skeleton), min_distance=5)
    return img, binary, skeleton, minutiae_points


img, binary_image, skeleton, minutiae_points = extract_minutiae(
    "data/sample_fingerprints/A.png"
)

fig, axes = plt.subplots(1, 3, figsize=(15, 5))

axes[0].imshow(img, cmap="gray")
axes[0].set_title("Original Image")

axes[1].imshow(binary_image, cmap="gray")
axes[1].set_title("Binary Image")

axes[2].imshow(skeleton, cmap="gray")
axes[2].scatter(
    minutiae_points[:, 1], minutiae_points[:, 0], c="red", s=15, label="Minutiae"
)
axes[2].set_title("Skeleton + Minutiae")
axes[2].legend()

plt.show()
