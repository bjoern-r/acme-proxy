FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl bash bind9-host \
    && rm -rf /var/lib/apt/lists/*

# Bake in the latest acme.sh release (used by app/backends/acmesh.py's default
# acme_sh_home: /opt/acme.sh) so the acmesh backend works without mounting anything.
RUN set -eux; \
    tag=$(curl -fsS -o /dev/null -w '%{redirect_url}' https://github.com/acmesh-official/acme.sh/releases/latest \
      | sed 's#.*/tag/##'); \
    mkdir -p /opt/acme.sh; \
    curl -fsSL "https://codeload.github.com/acmesh-official/acme.sh/tar.gz/refs/tags/${tag}" \
      | tar -xz -C /opt/acme.sh --strip-components=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

# Mount your real config.yaml at runtime, e.g.:
#   docker run -v $PWD/config.yaml:/srv/config.yaml -p 8000:8000 acme-proxy
#
# acme.sh is baked into the image at /opt/acme.sh (see above). To pin a version
# instead of always pulling latest at build time, mount your own checkout over it:
#   docker run -v /opt/acme.sh:/opt/acme.sh:ro ...

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
