import os
import requests
import gradio as gr
import json  # Import the json module

def process(video):
    url = "http://127.0.0.1:8000/api/video/generate_signature_from_video"
    directory = "/Users/robertbadinter/Desktop/doss"  # Adjust as necessary

    with open(video.name, 'rb') as f:
        video_content = f.read()

    files = {
        'video': (os.path.basename(video.name), video_content),
    }
    data = {
        'directory': directory
    }

    response = requests.post(url, files=files, data=data)
    response_json = response.json()  # Parse the JSON response

    # Format the response into a nicer string
    formatted_response = f"File Path: {response_json['file_path']}\nGenerate Signature: {response_json['generate_signature']}"
    
    return formatted_response

def verify(zip_file, video_file):
    url = "http://127.0.0.1:8000/api/video/verify_signature"

    with open(zip_file.name, 'rb') as f:
        zip_content = f.read()

    with open(video_file.name, 'rb') as f:
        video_content = f.read()

    files = [
        ('file', (os.path.basename(zip_file.name), zip_content)),
        ('video', (os.path.basename(video_file.name), video_content)),
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
        formatted_response = "The response from the API did not contain a 'result' field."

    return formatted_response

def interface(choice, video, zip_file=None):
    if choice == 'process':
        return process(video)
    elif choice == 'verify':
        if zip_file is None:
            return "Please upload a zip file for verification."
        else:
            return verify(zip_file, video)

iface = gr.Interface(
    fn=interface,
    inputs=[
        gr.Radio(['process', 'verify'], label="Choice"),
        gr.File(label="Video File"),
        gr.File(label="Zip File (only for verify)")
    ],
    outputs="text",
    title="Video Processing and Verification API",
    description="Upload a video to process or verify"
)

if __name__ == "__main__":
    iface.launch()