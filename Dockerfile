# ghcr.io/thoryn-io/thoryn-cli — the thoryn CLI as a container image (SSO-3687, parent SSO-3678).
#
# Built by .github/workflows/release.yml on every cli-v* tag, for linux/amd64 + linux/arm64, from the
# release's OWN linux native binaries (the `native` legs) — nothing is compiled here, so there is no
# RUN step and a cross-architecture build needs no emulation. The build context must contain
#
#   dist/thoryn-linux-amd64
#   dist/thoryn-linux-arm64
#
# (the release-asset names; buildx picks one per platform through TARGETARCH). To build one locally,
# put a linux native binary under that name and run e.g.
#
#   docker buildx build --platform linux/arm64 --load -t thoryn-cli:local .
#
# Base: distroless/cc. The native binary is NOT static — it links glibc (readelf NEEDED: libc.so.6 and
# ld-linux; zlib is linked statically on Linux, see cli/pom.xml `native-static-nolibc-linux`), so
# distroless/static cannot run it. distroless/cc carries glibc plus libgcc_s, which glibc loads on
# demand for thread unwinding (pthread_exit / pthread_cancel). No shell, no package manager.
#
# Pinned by digest (the multi-arch index of :nonroot). Bump it deliberately:
#   docker buildx imagetools inspect gcr.io/distroless/cc-debian12:nonroot
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

ARG TARGETARCH

LABEL org.opencontainers.image.title="thoryn" \
      org.opencontainers.image.description="The Thoryn customer-plane CLI — e.g. the Thoryn init container that fetches an application's own client secret." \
      org.opencontainers.image.source="https://github.com/thoryn-io/thoryn-cli" \
      org.opencontainers.image.url="https://github.com/thoryn-io/thoryn-cli"

COPY --chmod=0555 dist/thoryn-linux-${TARGETARCH} /usr/local/bin/thoryn

# distroless `nonroot` (uid/gid 65532), numeric so `runAsNonRoot: true` can verify it.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/thoryn"]
CMD ["--help"]
