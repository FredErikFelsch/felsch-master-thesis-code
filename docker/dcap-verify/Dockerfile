# x86_64 Linux with Intel's DCAP Quote Verification Library, for offline verification of
# recorded TDX quotes on machines without it (the library is x86_64 only). Build and run it
# with scripts/gke-v5/21_dcap_verify.sh. The PCS API key is passed at run time and is not part
# of the image.
FROM --platform=linux/amd64 ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
      python3 python3-cryptography python3-pyasn1 python3-requests && \
    install -d /etc/apt/keyrings && \
    curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor -o /etc/apt/keyrings/intel-sgx.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" > /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && apt-get install -y --no-install-recommends libsgx-dcap-quote-verify libsgx-dcap-default-qpl && \
    rm -rf /var/lib/apt/lists/*
RUN dpkg -l | awk '/libsgx-dcap-quote-verify|libsgx-dcap-default-qpl/ {print $2" "$3}' > /etc/dcap-versions.txt
COPY booking_v5/dcap /app/booking_v5/dcap
COPY booking_v5/__init__.py /app/booking_v5/__init__.py
COPY docker/dcap-verify/verify_probe_quote.py /app/verify_probe_quote.py
WORKDIR /app
ENV PYTHONPATH=/app
ENTRYPOINT ["python3", "/app/verify_probe_quote.py"]
