# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# LynxDB server for the LynxDB backend engine tests. The release tarball is
# fetched by URL and verified against the SHA-256 published in the release's
# checksums.txt.

FROM scratch AS fetch-amd64
ADD --checksum=sha256:7be3a6f29e601986ca0450a2d8e583a4cfb0f14c57f1eceebde86eddba43c0b0 \
    https://github.com/lynxbase/lynxdb/releases/download/v0.2.5/lynxdb-v0.2.5-linux-amd64.tar.gz /lynxdb.tar.gz

FROM scratch AS fetch-arm64
ADD --checksum=sha256:c68c407ae61badcd8872bbe77036919904014f591a66c4cd1db9b712d87cca3d \
    https://github.com/lynxbase/lynxdb/releases/download/v0.2.5/lynxdb-v0.2.5-linux-arm64.tar.gz /lynxdb.tar.gz

ARG TARGETARCH
FROM fetch-${TARGETARCH} AS fetch

FROM debian:stable-slim@sha256:eb593cf2c358cacef45ca0a424bbc7d30cfa3466265fc2662b9466a0ca6ba1c5
COPY --from=fetch /lynxdb.tar.gz /tmp/lynxdb.tar.gz
RUN tar -xzf /tmp/lynxdb.tar.gz -C /usr/local/bin lynxdb && rm /tmp/lynxdb.tar.gz
COPY run-cases.sh /usr/local/bin/run-cases.sh
ENTRYPOINT ["/usr/local/bin/run-cases.sh"]
