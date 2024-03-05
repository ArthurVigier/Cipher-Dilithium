import os
import requests
import gradio as gr
import json

def process(media, media_file):
    url = f"http://127.0.0.1:8000/api/{media}/generate_signature_from_{media}"
    directory = "/Users/robertbadinter/Desktop/doss"  # Adjust as necessary

    files = {
        media : (os.path.basename(media_file.name), media_file),
    }
    data = {
        'directory': directory
    }

    response = requests.post(url, files=files, data=data)
    response_json = response.json()  # Parse the JSON response

    formatted_response = f"File Ids: {response_json['file_ids']}\nGenerate Signature: {response_json['generate_signature']}"
    return formatted_response

def verify(media, zip_file, media_file):
    url = f"http://127.0.0.1:8000/api/{media}/verify_signature"

    with open(zip_file.name, 'rb') as f:
        zip_content = f.read()

    with open(media_file.name, 'rb') as f:
        media_content = f.read()

    files = [
        ('file', (os.path.basename(zip_file.name), zip_content)),
        (media, (os.path.basename(media_file.name), media_content)),
    ]

    response = requests.post(url, files=files)
    
    # Check if the response is a valid JSON
    try:
        response_json = response.json()  # Parse the JSON response
    except json.decoder.JSONDecodeError:
        return f"Invalid JSON response: {response.text}"

    # Check if 'result' is in the response
    if 'result' in response_json:
        # Format the response into a nicer string
        dilithium_result = response_json['result']['dilithium']
        ecc_result = response_json['result']['ecc']
        
        dilithium_success = dilithium_result['success']
        
        ecc_success = ecc_result['success']
        
        formatted_response = f"Dilithium Verification Result: Success - {dilithium_success}\nECC Verification Result: Success - {ecc_success}"
    else:
        formatted_response = response_json

    return formatted_response


def interface(choice, media_input, media_file, zip_file=None):
    if choice == 'process':
        return process(media_input, media_file)
    elif choice == 'verify':
        if zip_file is None:
            return "Please upload a zip file for verification."
        else:
            return verify(media_input, zip_file, media_file)

iface = gr.Interface(
    fn=interface,
    inputs=[
        gr.Radio(['process', 'verify'], label="Choice"),
        gr.Radio(['audio', 'video', 'image'], label="Media Type"),
        gr.File(label="Media File"),
        gr.File(label="Zip File (only for verify)")  # Making zip file optional for verify
    ],
    outputs="text",
    title="Media Processing and Verification API",
    description="Upload a media to process or verify"
)

if __name__ == "__main__":
    iface.launch()
