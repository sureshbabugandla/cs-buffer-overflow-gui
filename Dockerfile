# Buffer-overflow demo: compile the native binaries, then serve the Flask app.
# Single stage is fine here because we need gcc at build time and the binaries
# at run time. Runs on localhost only.
FROM python:3.12-slim

# Flush stdout/stderr immediately so log lines appear live in `docker logs`.
ENV PYTHONUNBUFFERED=1

# gcc, make AND the C standard library headers (stdio.h etc).
# build-essential bundles all three; installing bare "gcc" with
# --no-install-recommends omits libc6-dev and breaks #include <stdio.h>.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Build both the vulnerable and hardened binaries.
RUN make -C native all

EXPOSE 5000
CMD ["python", "app.py"]
