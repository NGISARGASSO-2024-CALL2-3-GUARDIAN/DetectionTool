import logging
from flask import Flask, request, jsonify
from mitm_attack_detector import MitMAtactDetector
from preprocessor import Preprocessor
from mitm_ai_detector import MitMAIDetector
import os

loggingLevel = logging.DEBUG
logging.basicConfig(level=loggingLevel, format="%(asctime)s:%(levelname)s:%(message)s")

app = Flask(__name__)

def save_file(file: str, directory: str):
    if not os.path.exists(directory):
        os.makedirs(directory)
    filepath = os.path.join(directory, file.filename)
    file.save(filepath)
    return filepath

@app.route('/detect/', methods=['POST'])
def execute():
    if 'file' not in request.files or 'process_per_transactions' not in request.form:
        return jsonify(error='No file or mode provided'), 400
    
    process_per_transactions = request.form['process_per_transactions']
    if process_per_transactions == 'true':  
        process_per_transactions = True
    else:
        process_per_transactions = False

    file = request.files['file']

    try:
        pcap_filepath = save_file(file, './pcaps')
        attack_detected = MitMAtactDetector(Preprocessor(), MitMAIDetector()).execute(process_per_transactions, pcap_filepath)
        os.remove(pcap_filepath)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500  

    return jsonify({'MitM_attack_detected': attack_detected})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)