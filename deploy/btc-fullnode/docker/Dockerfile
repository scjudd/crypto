FROM debian:latest AS builder

RUN apt-get update && apt-get install -y curl

RUN curl -O https://bitcoin.org/bin/bitcoin-core-0.20.0/bitcoin-0.20.0-x86_64-linux-gnu.tar.gz
RUN echo "35ec10f87b6bc1e44fd9cd1157e5dfa483eaf14d7d9a9c274774539e7824c427  bitcoin-0.20.0-x86_64-linux-gnu.tar.gz" | sha256sum -c
RUN tar -xzvf bitcoin-0.20.0-x86_64-linux-gnu.tar.gz

WORKDIR /rootfs

RUN mkdir -p etc/ var/lib/bitcoind/ \
    && echo "bitcoin:x:1000:1000::/var/lib/bitcoind:/bin/false" > etc/passwd \
    && echo "bitcoin:x:1000:" > etc/group \
    && chown 1000:1000 var/lib/bitcoind

RUN mkdir -p usr/bin/ lib64/ lib/ \
    && cp /bitcoin-0.20.0/bin/bitcoind \
          /bitcoin-0.20.0/bin/bitcoin-cli \
	  usr/bin/ \
    && cp /lib64/ld-linux-x86-64.so.2 \
          lib64/ \
    && cp /lib/x86_64-linux-gnu/libpthread.so.0 \
          /lib/x86_64-linux-gnu/librt.so.1 \
          /lib/x86_64-linux-gnu/libm.so.6 \
          /lib/x86_64-linux-gnu/libgcc_s.so.1 \
          /lib/x86_64-linux-gnu/libc.so.6 \
          lib/

FROM scratch

COPY --from=builder /rootfs/ /
COPY bitcoin.conf /etc/bitcoin/

ENTRYPOINT ["/usr/bin/bitcoind", "-conf=/etc/bitcoin/bitcoin.conf"]
USER bitcoin:bitcoin
VOLUME /var/lib/bitcoind
EXPOSE 8333 8332
