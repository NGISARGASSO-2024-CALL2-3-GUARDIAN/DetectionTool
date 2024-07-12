FROM python:3.9-slim

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y \
    wireshark \
    tshark \
    && rm -rf /var/lib/apt/lists/*	

COPY . /app
WORKDIR /app/src
RUN chmod +x models/packets_logistic_regression_sklearn.model
RUN chmod +x models/transact_logistic_regression_sklearn.model
RUN pip install -r ../requirements.txt
CMD ["python", "views.py"] 