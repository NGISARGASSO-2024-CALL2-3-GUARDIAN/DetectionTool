import pyshark
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
import logging
import asyncio

try:
    from tqdm import tqdm
except ImportError:
    print('tqdm no esta disponible; Los contadores de progreso estarán deshabilitados')

    def tqdm(it, *args, **kwargs):
        return it

class Preprocessor:
    def __init__(self):
        pass

    def process_per_packet_and_select_features(self, fpath: str, label: str) -> pd.DataFrame:
        logging.info('Adquisition and preprocessing packets...')
        df = self._process_per_packet(fpath, label)
        logging.info('Selecting AI model features...')   
        return df[['pkt_size', 'flow_duration', 'flow_bytes_per_second','x0_HTTP OK', 'x0_PSH-ACK', 'x0_Post']]
    
    def process_per_transaction_and_select_features(self, fpath: str, label: str) -> pd.DataFrame:
        logging.info('Adquisition and preprocessing transactions...')
        df = self._process_per_packet(fpath, label)
        df = self._process_per_transaction(df)
        logging.info('Selecting AI model features...')   
        return df[['flow_duration', 'flow_bytes_per_second','pkt_size', 'flow_duration_std', 'flow_bytes_per_second_std' ,'pkt_size_mean', 'packets_in_group']]
    
    def _process_per_packet(self, fpath: str, label: str) -> pd.DataFrame:
        """
        Extrae y prepara un DataFrame a partir de un archivo .pcap

        Args:
            fpath: El path al archivo .pcap con el que generar el DataFrame
            label: La etiqueta para todas las capturas del dataframe

        Returns:
            El DataFrame que contiene todas los paquetes en el archivo
        """

        loop = asyncio.new_event_loop() #TODO: DELETE?
        asyncio.set_event_loop(loop)    #TODO: DELETE?

        capture = pyshark.FileCapture(
            fpath,
            use_ek=True
        )

        features = {
            'timestamp': [],
            'pkt_size': [],
            'protocol': [],
            'flags': [],
            'flags_str': [],
            'status': [],
            'label': []
        }
        
        # Extracción de features 'primarias': 
        for packet in tqdm(capture, desc='Packets'):

            status    = float('nan')
            flags     = float('nan')
            flags_str = float('nan')

            if packet.highest_layer == 'HTTP':
                # status code != 100?
                try:
                    status = int(packet.http.response.code.value)
                except Exception as e:
                    print(e)
                    status = -1
            
            # asumimos que solo quedan tcp
            elif 'P' in packet.tcp.flags._all_fields['tcp_tcp_flags_str']:
                # flags
                #print((packet.tcp.flags._all_fields.items()))
                flags = int(packet.tcp.flags._all_fields['tcp_tcp_flags'], 16)
                flags_str = (packet.tcp.flags._all_fields['tcp_tcp_flags_str'])

            # es un ACK suelto (sin flag push); ignorar
            else:
                continue

            features['timestamp'].append(packet.frame_info.time_epoch)
            features['pkt_size'].append(len(packet))
            features['label'].append(label)
            features['protocol'].append(packet.highest_layer)

            features['flags'].append(flags)
            features['flags_str'].append(flags_str)
            features['status'].append(status)

        capture.close()
        loop.close()        #TODO: DELETE?
        df = pd.DataFrame(features)

        df.drop_duplicates('timestamp', inplace=True)

        df['packet_type'] = (df['status'].fillna(value=0) + df['flags'].fillna(value=0) + df['protocol'].map({
            'TCP_TCP_REASSEMBLED_DATA': 1,
            'TCP': 2,
            'HTTP': 0
        })).fillna(value=0).map({
            25: 'Post',
            26: 'PSH-ACK',
            100: 'HTTP Continue',
            200: 'HTTP OK'
        })

        # According to wireshark definitions (https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTimestamps.html)
        #  the timestamp is when the packet is first received. To calculate the full transmission time of the packet, difference with the previous should be shifted
        df['flow_duration'] = pd.to_datetime(df['timestamp']).astype('int64').astype(int).diff().shift(periods=-1)
            
        df['flow_bytes_per_second'] = df['pkt_size'] / df['flow_duration']
        
        # disregard flow duration of http ok since it is a response and the transfer is considered closed
        df.loc[ df['packet_type'] == 'HTTP OK', ['flow_duration', 'flow_bytes_per_second'] ] = float('nan')

        is_begin_of_transact = (df['protocol'] == 'TCP') & (df['flags'] == 0x0018)
        df['transaction_id'] = is_begin_of_transact.cumsum()


        ohe = OneHotEncoder()
        ohe_packet_type = ohe.fit_transform(df['packet_type'].values.reshape(-1, 1)).toarray()
        df[ohe.get_feature_names_out()] = ohe_packet_type
            

        df.reset_index(inplace=True, drop=True)
        return df.fillna(value=-1)

    def _process_per_transaction(self, df: pd.DataFrame) -> pd.DataFrame:        
        df = df.drop(columns=['flags_str', 'flags', 'status', 'protocol'])

        df.fillna(0, inplace=True)
        gb = df.groupby('transaction_id')

        df = gb.agg({
            'timestamp': 'max',
            'label': 'max',
            'flow_duration': 'sum',
            'flow_bytes_per_second': 'sum',
            'pkt_size': 'sum', 
        })

        df['flow_duration_std'] = gb['flow_duration'].std()
        df['flow_bytes_per_second_std'] = gb['flow_bytes_per_second'].std()
        df['pkt_size_mean'] = gb['pkt_size'].mean()
        df['packets_in_group'] = gb.size()

        df.reset_index(inplace=True, drop=True)
        return df.fillna(value=-1)