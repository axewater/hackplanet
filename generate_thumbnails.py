import os
from PIL import Image
from config import Config

def square_image(image, size):
    """Create a square thumbnail maintaining aspect ratio with black background."""
    image.thumbnail((size, size))
    if image.size[0] != size or image.size[1] != size:
        new_image = Image.new('RGB', (size, size), color='black')
        offset = ((size - image.size[0]) // 2, (size - image.size[1]) // 2)
        new_image.paste(image, offset)
        image = new_image
    return image

def generate_thumbnails():
    """Generate thumbnails for all JPG files in the gallery folder that don't have thumbnails."""
    gallery_path = os.path.join(Config.UPLOAD_FOLDER, 'avatars_users', 'gallery')
    
    if not os.path.exists(gallery_path):
        print(f"Gallery path does not exist: {gallery_path}")
        return

    # Get all jpg files in the gallery
    jpg_files = [f for f in os.listdir(gallery_path) if f.lower().endswith('.jpg')]
    
    for jpg_file in jpg_files:
        # Check if thumbnail already exists
        thumbnail_name = os.path.splitext(jpg_file)[0] + '_thumbnail.jpg'
        
        if not os.path.exists(os.path.join(gallery_path, thumbnail_name)):
            try:
                # Open and process the image
                with Image.open(os.path.join(gallery_path, jpg_file)) as img:
                    # Create thumbnail
                    thumb = square_image(img.copy(), 50)
                    # Save thumbnail
                    thumb_path = os.path.join(gallery_path, thumbnail_name)
                    thumb.save(thumb_path, "JPEG")
                    print(f"Created thumbnail for {jpg_file}")
            except Exception as e:
                print(f"Error processing {jpg_file}: {str(e)}")

if __name__ == "__main__":
    print("Starting thumbnail generation...")
    generate_thumbnails()
    print("Thumbnail generation complete!")
