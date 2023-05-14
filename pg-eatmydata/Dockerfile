FROM postgres:15.2
# keep in sync with docker-omposes

# eatmydata turns off sync
# only use in testing for a little extra speed
RUN apt update && \
    apt install -y eatmydata && \
    rm -rf /var/lib/apt/lists/*

ENV LD_PRELOAD=libeatmydata.so

