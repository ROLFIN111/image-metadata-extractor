import os
import hashlib
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
import exifread  # type: ignore

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit uploads to 16MB max

# Ensure the upload directory exists structurally
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def read_metadata(image_path):
    """Safely extracts image EXIF tags into clean string pairs."""
    try:
        clean_tags = {}
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            for key, val in tags.items():
                # Filter out raw binary/maker note tags for stable presentation
                if key not in ['JPEGThumbnail', 'TIFFThumbnail']:
                    clean_tags[str(key)] = str(val)
        return clean_tags if clean_tags else {"Status": "No EXIF metadata found inside this image asset."}
    except Exception as e:
        return {"Error": f"Forensic parsing failed: {str(e)}"}


def calculate_hashes(image_path):
    """Streams data blocks to calculate cryptographic checksum signatures."""
    try:
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()

        with open(image_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_md5.update(byte_block)
                hash_sha1.update(byte_block)
                hash_sha256.update(byte_block)

        return {
            "MD5": hash_md5.hexdigest(),
            "SHA1": hash_sha1.hexdigest(),
            "SHA256": hash_sha256.hexdigest()
        }
    except Exception as e:
        return {"Error": f"Hashing calculation failure: {str(e)}"}


@app.route('/upload', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({"Error": "No file stream container recognized."}), 400

    file = request.files['image']
    if not file or file.filename == '':
        return jsonify({"Error": "No image asset file selected."}), 400

    # Prevent directory traversal attacks using secure naming conventions
    filename = secure_filename(file.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(image_path)

        # Process metadata and checksum signatures
        metadata_tags = read_metadata(image_path)
        crypto_hashes = calculate_hashes(image_path)

        return render_template("index.html", metadata=metadata_tags, hashes=crypto_hashes)
    
    finally:
        # Optional: Delete file after parsing if you want to save storage space
        if os.path.exists(image_path):
            os.remove(image_path)


@app.route('/')
def home():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
