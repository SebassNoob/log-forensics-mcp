# The `cc` variant, not `base`: the napi addons link libgcc_s, and without it the
# server starts but every request fails when it dlopens them.
FROM gcr.io/distroless/cc-debian12:nonroot

ARG BINARY=dist/log-forensics-mcp-linux-x64
COPY --chmod=755 ${BINARY} /usr/local/bin/log-forensics-mcp

EXPOSE 3001

ENTRYPOINT ["log-forensics-mcp"]
