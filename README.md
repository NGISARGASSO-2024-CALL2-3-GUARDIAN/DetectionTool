# MITM detector 

## Table of Contents

- [Overview](#overview)
- [Usage](#usage)
  - [Endpoint](#endpoint)
  - [Example Usage with cURL](#example-usage-with-curl)
  - [Response](#response)
- [Installation](#installation)
  - [Deploying with Docker/Kubernetes](#deploying-with-docker)
- [License](#license)

## Overview

MITM Detector utilizes AI models to analyze network traffic contained within a PCAP file, aiming to detect Man-in-the-Middle (MitM) attacks.

- **Packet-by-Packet Analysis**: This approach inspects each packet individually to detect anomalies or suspicious patterns that may indicate a MitM attack.
  
- **Transaction-level Analysis**: Alternatively, the application can analyze network transactions, focusing on the interactions between entities to identify potential signs of a MitM attack.

## Usage

### Endpoint

The application exposes a single endpoint for detecting MitM attacks:

- **POST** `HOSTNAME:5000/detect/`

### Example usage with cURL

```bash
curl --location 'HOSTNAME:5000/detect/' \
--form 'process_per_packet="true"' \
--form 'file=@"/path/to/your/pcap/file.pcapng"'
```

#### Parameter Details

Replace `HOSTNAME` with the actual hostname where the MITM Detector API is hosted, and `/path/to/your/pcap/file.pcapng` with the path to the PCAP file you want to analyze.

- **`process_per_packet`**: Set this parameter to `"true"` or `"false"` depending on the type of processor being used for the analysis.
  - `"true"`: Enables packet-by-packet analysis.
  - `"false"`: Uses transaction-level analysis.

### Response
Upon analyzing the PCAP file, the application will respond with a JSON indicating whether a MitM attack was detected:
```
{
  "MitM_attack_detected": true
}
```

If no MitM attack is detected, the response will be:
```
{
  "MitM_attack_detected": false
}
```

## Installation

### Deploying with Docker/Kubernetes

## License

Licensed under [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).

