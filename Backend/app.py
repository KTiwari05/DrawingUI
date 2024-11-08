from flask import Flask, request, jsonify, make_response, send_file, abort
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from datetime import timedelta
from models import db, User
from PIL import Image
import fitz
import io
import os
import tempfile
from werkzeug.utils import safe_join

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])

# Configuration settings
app.config.from_object("config.ApplicationConfig")
app.config['JWT_SECRET_KEY'] = app.config['SECRET_KEY']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'  # Ensure consistency
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable CSRF protection

app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB file limit

# Disable CSRF protection for API routes (if using Flask-WTF or Flask-SeaSurf)
app.config['WTF_CSRF_ENABLED'] = False

jwt = JWTManager(app)
bcrypt = Bcrypt(app)
db.init_app(app)

with app.app_context():
    db.create_all()

# User registration route
@app.route("/register", methods=["POST"])
def register_user():
    data = request.json
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"message": "Email and password are required"}), 400

    user_exists = User.query.filter_by(email=data["email"]).first() is not None
    if user_exists:
        return jsonify({"message": "User with that email already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    new_user = User(email=data["email"], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"id": new_user.id, "email": new_user.email}), 201

# User login route
@app.route("/login", methods=["POST"])
def login_user():
    data = request.json
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"message": "Email and password are required"}), 400

    user = User.query.filter_by(email=data["email"]).first()
    if user is None or not bcrypt.check_password_hash(user.password, data["password"]):
        return jsonify({"message": "Invalid email or password"}), 401

    access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1/2))
    response = make_response(jsonify({
        "message": "Login successful",
        "id": user.id,
        "email": user.email,
        "token": access_token
    }))
    response.set_cookie(
        'access_token_cookie',
        access_token,
        httponly=True,
        samesite='Lax',
        path='/'
    )

    return response, 200

# User logout route
@app.route("/logout", methods=["POST"])
@jwt_required()
def logout_user():
    response = make_response(jsonify({"message": "Logout successful"}))
    response.delete_cookie('access_token_cookie', path='/')
    return response, 200

# Get current user route
@app.route("/@me", methods=["GET"])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({"id": user.id, "email": user.email}), 200

# PDF to image conversion function
def pdftoimg(pdf_file):
    try:
        doc = fitz.open(pdf_file)
        page = doc.load_page(0)
        pix = page.get_pixmap()
        img = Image.open(io.BytesIO(pix.tobytes()))
        return img
    except Exception as e:
        print(f"Error converting PDF to image: {str(e)}")
        raise

# Make image transparent function
def make_image_transparent(image):
    img = image.convert("RGBA")
    datas = img.getdata()
    newData = []
    for item in datas:
        if item[0] == 255 and item[1] == 255 and item[2] == 255:
            newData.append((255, 255, 255, 0))
        else:
            newData.append(item)
    img.putdata(newData)
    return img

# Image comparison function
def compare_image(image1, image2):
    img1 = image1.convert("RGBA")
    img2 = image2.convert("RGBA")
    img2 = img2.resize(img1.size)
    datas1 = img1.getdata()
    datas2 = img2.getdata()
    newData = []
    for i in range(len(datas1)):
        if datas1[i] == datas2[i]:
            newData.append(datas1[i])
        else:
            newData.append((255, 0, 255))
    img2.putdata(newData)
    return img2

# PDF comparison route
@app.route('/compare', methods=['POST'])
@jwt_required()
def compare_files():
    try:
        user_id = get_jwt_identity()
        print(f"Authenticated user ID: {user_id}")

        if 'file1' not in request.files or 'file2' not in request.files:
            print("Missing files in the request.")
            return jsonify({"error": "Both files are required for comparison."}), 400

        file1 = request.files['file1']
        file2 = request.files['file2']

        if not file1 or not file2:
            print("One or both files are empty.")
            return jsonify({"error": "Both files must be uploaded."}), 400

        # Temporary file storage
        temp_file1 = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        temp_file2 = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        file1.save(temp_file1.name)
        file2.save(temp_file2.name)
        print(f"Files saved to temporary location: {temp_file1.name}, {temp_file2.name}")

        # Convert PDF to image
        img1 = pdftoimg(temp_file1.name)
        img2 = pdftoimg(temp_file2.name)
        print("PDF files successfully converted to images.")

        # Make images transparent
        img1 = make_image_transparent(img1)
        img2 = make_image_transparent(img2)
        print("Images made transparent.")

        # Compare images
        compared_img = compare_image(img1, img2)
        print("Images compared successfully.")

        # Save the compared image as a PDF
        temp_output_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        compared_img.convert("RGB").save(temp_output_pdf.name, "PDF")
        print(f"Comparison PDF saved at {temp_output_pdf.name}")

        # Generate download URL
        filename = os.path.basename(temp_output_pdf.name)
        download_url = f"http://localhost:5000/download/{filename}"

        # Return the download URL as JSON
        return jsonify({"download_url": download_url}), 200

    except Exception as e:
        print(f"Error processing files: {str(e)}")
        return jsonify({"error": f"Error processing files: {str(e)}"}), 500

    finally:
        # Clean up temporary files
        try:
            os.unlink(temp_file1.name)
            os.unlink(temp_file2.name)
            print("Temporary files cleaned up.")
        except Exception as e:
            print(f"Error cleaning up temporary files: {str(e)}")

# Flask endpoint to send the comparison result for download (optional)
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    file_path = safe_join(tempfile.gettempdir(), filename)
    if not os.path.exists(file_path):
        abort(404)
    try:
        response = send_file(file_path, as_attachment=True, mimetype='application/pdf')
        # Schedule the file for deletion after sending
        @response.call_on_close
        def remove_file():
            try:
                os.unlink(file_path)
                print(f"Deleted temporary file: {file_path}")
            except Exception as e:
                print(f"Error deleting file {file_path}: {str(e)}")
        return response
    except Exception as e:
        return jsonify({"error": f"Failed to download file: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)