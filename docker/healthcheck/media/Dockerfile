# Disposable media proof dependencies; never used as the deployed gateway image.
ARG GATEWAY_IMAGE
FROM ${GATEWAY_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-aiortc python3-numpy espeak-ng \
 && rm -rf /var/lib/apt/lists/*
