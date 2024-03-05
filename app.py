# app.py
from flask import Flask
from flask_cors import CORS
from apis.audio_python_api import audio_api
from apis.image_api import image_api
from apis.video_api import video_api
import redis

app = Flask(__name__)
CORS(app)
app.register_blueprint(audio_api, url_prefix='/api/audio')
app.register_blueprint(image_api, url_prefix='/api/image')
app.register_blueprint(video_api, url_prefix='/api/video')

# Créer un client Redis
r = redis.Redis(host='localhost', port=8000, db=0)

if __name__ == '__main__':
    app.run(debug=True)

# routes présentes dans audio_python_api.py : generate_signature_route, generate_signature_from_audio_route , verify_signature_route
# nom des routes : /api/generate_signature, /api/generate_signature_from_audio, /api/verify_signature

# routes présentes dans image_api.py : generate_signature_route, generate_signature_from_image_route
# nom des routes : /api/generate_signature, /api/generate_signature_from_image , /api/verify_signature
    
# routes présentes dans video_api.py : generate_signature_route, generate_signature_from_video_route
# nom des routes : /api/generate_signature, /api/generate_signature_from_video , /api/verify_signature
