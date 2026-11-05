FROM golang:1.26-bookworm AS tools
ENV GOTOOLCHAIN=auto
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/PentestPad/subzy@latest \
 && go install github.com/tomnomnom/assetfinder@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/gwen001/github-subdomains@latest \
 && go install github.com/gwen001/gitlab-subdomains@latest \
 && go install github.com/projectdiscovery/uncover/cmd/uncover@latest \
 && go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest \
 && go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends whois ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /go/bin/ /usr/local/bin/
RUN pip install --no-cache-dir "mcp[cli]<2"
RUN pip install --no-cache-dir shodan || echo "shodan pip skipped"
RUN pip install --no-cache-dir theHarvester || echo "theHarvester install skipped"
RUN arch="$(uname -m)"; \
    case "$arch" in \
      x86_64)  f="findomain-linux" ;; \
      aarch64) f="findomain-aarch64" ;; \
      *)       f="" ;; \
    esac; \
    if [ -n "$f" ]; then \
      ( curl -fsSL "https://github.com/Findomain/Findomain/releases/latest/download/$f.zip" -o /tmp/fd.zip \
          && unzip -o /tmp/fd.zip -d /usr/local/bin/ && chmod +x /usr/local/bin/findomain ) \
      || ( curl -fsSL "https://github.com/Findomain/Findomain/releases/latest/download/$f" -o /usr/local/bin/findomain \
          && chmod +x /usr/local/bin/findomain ) \
      || echo "findomain install skipped"; \
    else echo "findomain skipped (unsupported arch $arch)"; fi; \
    rm -f /tmp/fd.zip || true
WORKDIR /app
COPY server.py verify.py ./
ENV HARNESS_DB=/data/harness.db
EXPOSE 8000
CMD ["python", "server.py"]
