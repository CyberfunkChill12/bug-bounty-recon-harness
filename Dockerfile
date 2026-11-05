FROM golang:1.26-bookworm AS tools
ENV GOTOOLCHAIN=auto
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/PentestPad/subzy@latest

FROM python:3.12-slim
COPY --from=tools /go/bin/ /usr/local/bin/
RUN pip install --no-cache-dir "mcp[cli]<2"
WORKDIR /app
COPY server.py .
ENV HARNESS_DB=/data/harness.db
EXPOSE 8000
CMD ["python", "server.py"]
