import logging


class MitMAtactDetector:
    def __init__(self, preprocessor,  mitm_ai_detector) -> None:
        self.preprocessor = preprocessor
        self.mitm_ai_detector = mitm_ai_detector

    def execute(self, filepath: str) -> bool: 
        logging.info('Starting...')
        return self._process_per_transactions(filepath)

    def _process_per_packets(self, filepath: str) -> bool: 
        logging.info('Process by packet selected')
        features = self.preprocessor.process_per_packet_and_select_features(filepath, 'mitm')
        # logging.info("feature: ", features)         #TODO: delete
        return self.mitm_ai_detector.execute_packets_model(features)

    def _process_per_transactions(self, filepath: str) -> bool:
        logging.info('Process by transaction selected')
        features = self.preprocessor.process_per_transaction_and_select_features(filepath, 'mitm')
        # logging.info("feature: ", features)         #TODO: delete
        return self.mitm_ai_detector.execute_transaction_model(features)