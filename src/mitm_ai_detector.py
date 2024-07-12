import logging
import pickle
from pandas import DataFrame
import numpy as np
import os


class MitMAIDetector:
    def __init__(self):
        ...

    def execute_packets_model(self, features: DataFrame) -> bool:
        logging.info('Starting the model inference for MitM detection...')
        packets_model = pickle.load(open('./models/packets_logistic_regression_sklearn.model', 'rb'))
        mitm_predictions = packets_model.predict(features)  
        high_attack_probability = self._is_mitm_attack_likely(mitm_predictions)
        return True if high_attack_probability else False
        
    def execute_transaction_model(self, features: DataFrame) -> bool:
        logging.info('Starting the model inference for MitM detection...')
        transact_model = pickle.load(open('./models/transact_logistic_regression_sklearn.model', 'rb'))    
        mitm_predictions = transact_model.predict(features) 
        high_attack_probability = self._is_mitm_attack_likely(mitm_predictions)
        return True if high_attack_probability else False
    
    def _is_mitm_attack_likely(self, predictions):
        total_predictions = predictions.size
        num_mitm_attack_detections = np.sum(predictions == 1)
        mitm_attack_probability_percentage = (num_mitm_attack_detections / total_predictions) * 100
        return mitm_attack_probability_percentage > 80