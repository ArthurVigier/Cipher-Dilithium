from flask import Flask, request, jsonify , Blueprint
import os
import base64
import io
import uuid
import ast
import json
from datetime import datetime
from dilithium import Dilithium
import zipfile
import pickle
import logging
app = Flask(__name__)

# Durée de l'enregistrement en secondes
RECORD_SECONDS = 5
# Fréquence d'échantillonnage
SAMPLE_RATE = 44100
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def generate_signature(message):
    # Générer une clé privée
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Signer le message
    ecc_signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    # Obtenir la clé publique
    ecc_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Dilithium signature generation
    dilithium_signer = Dilithium()  # Create a Dilithium signer instance
    pq_signature = dilithium_signer.sign(message)

    # Conserver la clé publique Dilithium sous sa forme originale
    pq_public_key = dilithium_signer.pk

    print(f"pq_signature format: {type(pq_signature)}")
    print(f"pq_public_key format: {type(pq_public_key)}")
    return pq_signature, ecc_signature, pq_public_key, ecc_public_key



def verify_signature(message, pq_signature, pq_public_key , ecc_signature, ecc_public_key):
    # Vérifier si le message est fourni
    if not message:
        raise ValueError("Le message est requis pour la vérification de la signature.")
    # Afficher les valeurs des signatures et des clés publiques


    # Initialiser les vérificateurs
    dilithium_verifier = Dilithium()
    ecc_verifier = ec.ECDSA(hashes.SHA256())

    # Créer un dictionnaire pour stocker les résultats
    results = {'dilithium': {'success': None, 'error': None}, 'ecc': {'success': None, 'error': None}}

    # Tenter la vérification Dilithium
    try:
        print("Début de la vérification Dilithium")
        pk = pickle.loads(pq_public_key)
        print("Clé publique Dilithium chargée")
        results['dilithium']['success'] = dilithium_verifier.verify(message, pickle.loads(pq_signature), pk)
        print("Vérification Dilithium terminée")
    except Exception as e:
        print(f"Erreur lors de la vérification Dilithium : {e}")
        results['dilithium']['success'] = False
        results['dilithium']['error'] = str(e)

    # Tenter la vérification ECC
    try:
        print("Début de la vérification ECC")
        public_key = serialization.load_pem_public_key(ecc_public_key)
        print("Clé publique ECC chargée")
        public_key.verify(ecc_signature, message, ecc_verifier)
        print("Vérification ECC terminée")
        results['ecc']['success'] = True
    except InvalidSignature as e:
        print("Erreur lors de la vérification ECC : signature invalide")
        results['ecc']['success'] = False
        results['ecc']['error'] = 'Signature invalide'

    return results

# Créez une instance de Blueprint
audio_api = Blueprint('audio_api', __name__)


@audio_api.route('/generate_signature', methods=['POST'])
def generate_signature_route():
    message = request.json.get('message')
    if not message:
        return jsonify({"error": "No message provided"}), 400

    # Convert the message to bytes if it's not already
    if isinstance(message, str):
        message = message.encode()

    pq_signature_str, ecc_signature, pq_public_key_str, ecc_public_key = generate_signature(message)

    return jsonify({
        'pq_signature_str': pq_signature_str,
        'ecc_signature': ecc_signature,
        'public_key_str': pq_public_key_str,
        'ecc_public_key': ecc_public_key,
        'message': 'Signature generated successfully',
    })




@audio_api.route('/generate_signature_from_audio', methods=['POST'])
def generate_signature_from_audio_route():
    # Check if an audio file was provided
    if 'audio' not in request.files:
        return "No audio file provided", 400

    audio_files = request.files.getlist('audio')

    output_data = []

    for audio_file in audio_files:
        # Read the audio file data
        audio_data = audio_file.read()

        # Use the audio data as the message for generate_signature
        pq_signature, ecc_signature, pq_public_key, ecc_public_key = generate_signature(audio_data)

       

        # Prepare the data to be written to the file
        data = {
            'message': audio_data,
            'pq_signature': pq_signature,
            'ecc_signature': ecc_signature,
            'pq_public_key': pq_public_key,
            'ecc_public_key': ecc_public_key,
            'date': datetime.now().isoformat()  # Add the current date and time
        }

        # Get the file name from the audio file and replace the extension with .zip
        file_name, _ = os.path.splitext(audio_file.filename)
        file_name += '.zip'

        # Write the data to a zip file
        with zipfile.ZipFile(file_name, 'w') as zipf:
            for key, value in data.items():
                if key == 'ecc_public_key':
                    # Keep ecc_public_key in PEM format and write it to a .txt file
                    zipf.writestr(f'{key}.txt', value.decode('utf-8'))
                elif key in ['pq_signature', 'pq_public_key', 'message', 'ecc_signature']:  # Add 'ecc_signature' here
                    # Convert tuples to bytes and keep 'message' and 'ecc_signature' as bytes
                    if key not in ['message', 'ecc_signature']:  # Exclude 'message' and 'ecc_signature' from conversion
                        value = pickle.dumps(value)
                    zipf.writestr(f'{key}.bin', value)
                else:
                    # Convert other values to strings
                    value = str(value).encode('utf-8')
                    zipf.writestr(f'{key}.bin', value)

        # Print the file path
        print(f'File saved at: {file_name}')

        output_data.append(data)
    return jsonify({"generate_signature": "success", "file_path": file_name})



@audio_api.route('/verify_signature', methods=['POST'])
def verify_signature_route():
    app.logger.info('Entered verify_signature_route')
    # Check if a file was provided
    if 'file' not in request.files or 'audio' not in request.files:
        return jsonify({"error": "No file or audio provided"}), 400

    file = request.files['file']
    audio_file = request.files['audio']

    app.logger.info('File and audio received for signature verification')

    # Read the file data
    zip_file = zipfile.ZipFile(io.BytesIO(file.read()))

    data = {}
    for filename in zip_file.namelist():
        with zip_file.open(filename) as f:
            key = filename.rsplit('.', 1)[0]
            value = f.read()
            data[key] = value
    
    audio_data = audio_file.read()

        # Compare the image data with the one from the zip file
    if audio_data != data['message']:
        return jsonify({'result comparison': False})
    
    app.logger.info('Comparison successful')
    # Call the verify_signature function with the original data
    result = verify_signature(
        data['message'], data['pq_signature'], data['pq_public_key'], data['ecc_signature'], data['ecc_public_key']
    )

    # Return the result as a JSON response
    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)


"""
    # Check if result is -16 and modify the message accordingly
    if result == -16:
        result_message = 'ECDSA_VERIFY success '
    else:
        result_message = f'Result of verification: {result}'

"""