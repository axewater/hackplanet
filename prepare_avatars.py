import os
from PIL import Image
from config import Config

def square_image(image, size):
    """Create a square image maintaining aspect ratio with black background."""
    image.thumbnail((size, size))
    if image.size[0] != size or image.size[1] != size:
        new_image = Image.new('RGB', (size, size), color='black')
        offset = ((size - image.size[0]) // 2, (size - image.size[1]) // 2)
        new_image.paste(image, offset)
        image = new_image
    return image

def process_avatars():
    """Convert WEBP files to JPG and generate thumbnails."""
    gallery_path = os.path.join(Config.UPLOAD_FOLDER, 'avatars_users', 'gallery')
    
    if not os.path.exists(gallery_path):
        print(f"Gallery path does not exist: {gallery_path}")
        return

    # Get all webp files in the gallery
    webp_files = [f for f in os.listdir(gallery_path) if f.lower().endswith('.webp')]
    
    if not webp_files:
        print("No WEBP files found in the gallery.")
        return

    for webp_file in webp_files:
        try:
            # Open WEBP file
            with Image.open(os.path.join(gallery_path, webp_file)) as img:
                # Convert to RGB mode if necessary
                if img.mode in ('RGBA', 'LA'):
                    background = Image.new('RGB', img.size, (0, 0, 0))
                    background.paste(img, mask=img.split()[-1])
                    img = background
                elif img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Create 512x512 version
                main_image = square_image(img.copy(), 512)
                
                # Save as JPG
                jpg_filename = os.path.splitext(webp_file)[0] + '.jpg'
                jpg_path = os.path.join(gallery_path, jpg_filename)
                main_image.save(jpg_path, "JPEG", quality=95)
                
                # Create and save thumbnail
                thumb = square_image(img.copy(), 50)
                thumb_path = os.path.join(gallery_path, os.path.splitext(jpg_filename)[0] + '_thumbnail.jpg')
                thumb.save(thumb_path, "JPEG", quality=95)
                
                print(f"Processed {webp_file} -> {jpg_filename}")
                
        except Exception as e:
            print(f"Error processing {webp_file}: {str(e)}")

if __name__ == "__main__":
    print("Starting avatar processing...")
    process_avatars()
    print("Avatar processing complete!")
