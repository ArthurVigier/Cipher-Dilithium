from flask import Flask, request, jsonify
import ctypes
import os
from ctypes import cdll , c_ulong, c_uint8, c_size_t, POINTER
import base64
import io
import uuid
import ast
import json
from datetime import datetime
import logging
app = Flask(__name__)

# Durée de l'enregistrement en secondes
RECORD_SECONDS = 5
# Fréquence d'échantillonnage
SAMPLE_RATE = 44100
# Load the shared library
pqcrypto_utils = cdll.LoadLibrary('/Users/robertbadinter/VoCipher/src/audio/corrected_pqcrypto_utils.so')


# Define the return type of the function get_length_public_key
pqcrypto_utils.get_length_public_key.restype = ctypes.c_size_t

# Call the function get_length_public_key
length_public_key = pqcrypto_utils.get_length_public_key()

# Configurer le journalisation
logging.basicConfig(level=logging.DEBUG)


# Update the argtypes to include out_signature_pq_len and out_ecc_signature_len
pqcrypto_utils.generate_signature.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  # message
    ctypes.c_size_t,                 # message_len
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),  # out_pq_signature
    ctypes.POINTER(ctypes.c_size_t),                 # out_pq_signature_len
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),  # out_ecc_signature
    ctypes.POINTER(ctypes.c_uint),                   # out_ecc_signature_len, adjusted to c_uint
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),  # out_public_key
    ctypes.POINTER(ctypes.c_size_t),                 # out_public_key_len
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),  # out_ecc_public_key
    ctypes.POINTER(ctypes.c_size_t),                 # out_ecc_public_key_len
]


# Définir le type de retour pour la fonction generate_signature
pqcrypto_utils.generate_signature.restype = ctypes.c_int

def generate_signature(message):
    message_buffer = (ctypes.c_ubyte * len(message))(*message)

    # Correctly initializing the output parameters as pointers to pointers
    out_pq_signature = ctypes.POINTER(ctypes.c_uint8)()
    out_pq_signature_len = ctypes.c_size_t()
    out_ecc_signature = ctypes.POINTER(ctypes.c_uint8)()  
    out_ecc_signature_len = ctypes.c_uint()
    out_public_key = ctypes.POINTER(ctypes.c_uint8)()
    out_public_key_len = ctypes.c_size_t()
    out_ecc_public_key = ctypes.POINTER(ctypes.c_uint8)()
    out_ecc_public_key_len = ctypes.c_size_t()

    # Correct the call to the C function according to its expected signature
    # Corrected call (assuming your function and variable setup is correct elsewhere)
    result = pqcrypto_utils.generate_signature(
        message_buffer,  # Pass the array directly
        len(message),
        out_pq_signature,  # Pass the pointer to pointer directly
        ctypes.byref(out_pq_signature_len),
        out_ecc_signature,  # Pass the pointer to pointer directly
        ctypes.byref(out_ecc_signature_len),
        out_public_key,  # Pass the pointer to pointer directly
        ctypes.byref(out_public_key_len),
        out_ecc_public_key,  # Pass the pointer to pointer directly
        ctypes.byref(out_ecc_public_key_len)
    )

    # Rest of your code...

    if result != 0:
        raise Exception(f"generate_signature failed with error code {result}")

    # Convert the outputs from ctypes to Python types
    pq_signature = [out_pq_signature[i] for i in range(out_pq_signature_len.value)]
    ecc_signature = bytes(out_ecc_signature[i] for i in range(out_ecc_signature_len.value))
    public_key = [out_public_key[i] for i in range(out_public_key_len.value)]
    
    # Convert the ECC public key from ctypes pointer to Python bytes directly
    ecc_public_key = ctypes.string_at(out_ecc_public_key, out_ecc_public_key_len.value) # Directly convert the pointer to bytes

    pq_signature_len = ctypes.c_size_t(out_pq_signature_len.value)  # Nouveau
    ecc_signature_len = ctypes.c_size_t(out_ecc_signature_len.value)
    return pq_signature, ecc_signature, public_key, ecc_public_key, pq_signature_len, ecc_signature_len



# Créez une variable message_len
serious_message_len = ctypes.c_size_t(32)


# Create pointers for the message, signature and the public key
out_message = ctypes.POINTER(ctypes.c_uint8)()
out_message_len = ctypes.c_size_t()
out_pq_signature = ctypes.POINTER(ctypes.c_uint8)()
out_signature_len = ctypes.c_size_t()
out_public_key = ctypes.POINTER(ctypes.c_uint8)()
out_public_key_len = ctypes.c_size_t()
out_ecc_public_key = ctypes.POINTER(ctypes.c_uint8)()
out_ecc_public_key_len = ctypes.c_size_t()

# Convert length_public_key to ctypes.c_size_t
length_public_key_ctypes = ctypes.c_size_t(length_public_key)

@app.route('/generate_signature', methods=['POST'])
def generate_signature_route():
    message = request.json.get('message')
    if not message:
        return jsonify({"error": "No message provided"}), 400

    # Convert the message to bytes if it's not already
    if isinstance(message, str):
        message = message.encode()

    pq_signature, ecc_signature, public_key, ecc_public_key, pq_signature_len, ecc_signature_len = generate_signature(message)

    return jsonify({
        'pq_signature': list(pq_signature),
        'ecc_signature': base64.b64encode(ecc_signature).decode(),
        'public_key': list(public_key),
        'ecc_public_key': base64.b64encode(ecc_public_key).decode(),
        'pq_signature_len': pq_signature_len.value,
        'ecc_signature_len': ecc_signature_len.value,
        'message': 'Signature generated successfully',
    })

def verify_signature( message, message_len, signature_pq, signature_pq_len, signature_ecc, signature_ecc_len, public_key, public_key_len, ecc_public_key, ecc_public_key_len):
            # Appeler la fonction avec les pointeurs et les longueurs originales
            result = pqcrypto_utils.verify_signature(
                ctypes.cast(message, ctypes.POINTER(ctypes.c_ubyte)),
                message_len,
                signature_pq,
                signature_pq_len,
                ctypes.cast(signature_ecc, ctypes.POINTER(ctypes.c_ubyte)),
                signature_ecc_len,
                public_key,
                public_key_len,
                ctypes.cast(ecc_public_key, ctypes.POINTER(ctypes.c_ubyte)),
                ecc_public_key_len
            ) 
            return result


@app.route('/generate_signature_from_audio', methods=['POST'])
def generate_signature_from_audio_route():
    # Check if an audio file was provided
    if 'audio' not in request.files:
        return jsonify({"error": "No audio file provided"}), 400

    audio_files = request.files.getlist('audio')

    output_data = []

    for audio_file in audio_files:
        # Read the audio file data
        audio_data = audio_file.read()

        # Use the audio data as the message for generate_signature
        pq_signature, ecc_signature, public_key, ecc_public_key, pq_signature_len, ecc_signature_len = generate_signature(audio_data)

        # Prepare the data to be written to the file
        data = {
            'pq_signature': list(pq_signature),
            'ecc_signature': base64.b64encode(ecc_signature).decode(),
            'public_key': list(public_key),
            'public_key_len': len(public_key),
            'ecc_public_key': base64.b64encode(ecc_public_key).decode(),
            'ecc_public_key_len': len(ecc_public_key),
            'pq_signature_len': len(pq_signature),
            'ecc_signature_len': ecc_signature_len.value,
            'message': base64.b64encode(audio_data).decode(),  # Encode audio data in base64
            'message_len': len(audio_data),  # Add the length of the audio data
            'date': datetime.now().isoformat()  # Add the current date and time
        }

        # Get the file name from the audio file and replace the extension with .json
        file_name, _ = os.path.splitext(audio_file.filename)
        file_name += '.json'

        # Write the data to a json file
        with open(file_name, 'w') as f:
            json.dump(data, f)

        # Print the file path
        print(f'File saved at: {file_name}')

        output_data.append(data)

    return jsonify(output_data)

@app.route('/verify_signature', methods=['POST'])
def verify_signature_route():
    app.logger.info('Entered verify_signature_route')
    # Check if a file was provided
    if 'file' not in request.files or 'audio' not in request.files:
        return jsonify({"error": "No file or audio provided"}), 400

    file = request.files['file']
    audio_file = request.files['audio']

    app.logger.info('File and audio received for signature verification')

    # Read the file data
    file_data = file.read().decode()

    # Convert the file data from JSON to dictionary
    data = json.loads(file_data)

    # Read the audio data
    audio_data = audio_file.read()

    # Convert the binary audio data to a string
    audio_data_str = base64.b64encode(audio_data).decode()

    # Check if the audio data matches the message in the file
    if audio_data_str != data['message']:
        return jsonify({"error": "Audio data does not match message"}), 400
    
    app.logger.info('Audio data matches message')

    message = ''
    message_len = 0
    signature_pq = ''
    signature_pq_len = 0
    signature_ecc = ''
    signature_ecc_len = 0
    public_key = ''
    public_key_len = 0
    ecc_public_key = ''
    ecc_public_key_len = 0

    # Traitement des données ici

    message = data['message']
    message_len = len(message)
    signature_pq = (ctypes.c_uint8 * len(data['pq_signature']))(*data['pq_signature'])
    signature_pq_len = len(data['pq_signature'])
    signature_ecc = data['ecc_signature']
    signature_ecc_len = len(signature_ecc)
    public_key = (ctypes.c_uint8 * len(data['public_key']))(*data['public_key'])
    public_key_len = len(data['public_key'])
    ecc_public_key = data['ecc_public_key']
    ecc_public_key_len = len(ecc_public_key)
    
    print("Type de message :", type(message))
    print("Type de signature_pq :", type(signature_pq))
    print("Type de signature_ecc :", type(signature_ecc))
    print("Type de public_key :", type(public_key))
    print("Type de ecc_public_key :", type(ecc_public_key))

    print("Type de message_len :", type(message_len))
    print("Type de signature_pq_len :", type(signature_pq_len))
    print("Type de signature_ecc_len :", type(signature_ecc_len))
    print("Type de public_key_len :", type(public_key_len))
    print("Type de ecc_public_key_len :", type(ecc_public_key_len))
        
  
    # Call the verify_signature function with the original data
    result = verify_signature(
        message, message_len, signature_pq, signature_pq_len,
        signature_ecc, signature_ecc_len, public_key, public_key_len,
        ecc_public_key, ecc_public_key_len
    )

    # Check if result is -16 and modify the message accordingly
    if result == -16:
        result_message = 'ECDSA_VERIFY success and presence of PQ signature'
    else:
        result_message = f'Result of verification: {result}'

    app.logger.info(result_message)

    # Return the result as a JSON response
    return jsonify({'result': result_message})

if __name__ == '__main__':
    app.run(debug=True)

"""
    # Check if result is -16 and modify the message accordingly
    if result == -16:
        result_message = 'ECDSA_VERIFY success '
    else:
        result_message = f'Result of verification: {result}'

"""