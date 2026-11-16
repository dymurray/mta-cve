# One image for the bridge (Maven, Go and Python projects): the sbom-discovery and
# cve-remediation addons plus the cve-watcher. rgctl is the static musl build:
# the gnu build of 0.4.27 requires glibc >= 2.43, newer than any UBI.
FROM registry.access.redhat.com/ubi10/go-toolset:latest AS build
ENV GOTOOLCHAIN=auto GOFLAGS=-mod=mod
COPY --chown=1001:0 . /opt/app-root/src/bridge
WORKDIR /opt/app-root/src/bridge
RUN CGO_ENABLED=0 go build -o /opt/app-root/bin/ ./cmd/...

FROM registry.access.redhat.com/ubi10/openjdk-21:latest
USER root
RUN microdnf -y install git openssh-clients glibc-langpack-en tar gzip golang python3 python3-pip && microdnf clean all
# Python lock-file tools: uv.lock / poetry.lock are regenerated for the
# updated package only.
RUN python3 -m pip install --no-cache-dir --prefix /usr/local uv==0.5.11 poetry==2.1.1
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin v1.18.1
RUN echo "addon:x:1001:0:addon user:/addon:/sbin/nologin" >> /etc/passwd && \
    mkdir -p /etc/ssh/ssh_config.d && \
    printf 'StrictHostKeyChecking no\nUserKnownHostsFile /dev/null\n' > /etc/ssh/ssh_config.d/99-konveyor.conf
ARG RGCTL_VERSION=0.4.27
ARG RGCTL_SHA256=7cc3e7a94fe76d61101505e558fc1ca0dc385236b112d688daed9a76b1ce3fab
RUN curl -sSfL -o /tmp/rgctl.tgz \
      https://github.com/sshaaf/rgctl/releases/download/v${RGCTL_VERSION}/rgctl-${RGCTL_VERSION}-x86_64-unknown-linux-musl.tar.gz && \
    echo "${RGCTL_SHA256}  /tmp/rgctl.tgz" | sha256sum -c - && \
    tar -xzf /tmp/rgctl.tgz -C /usr/local/bin rgctl && rm /tmp/rgctl.tgz
COPY --from=build /opt/app-root/bin/ /usr/bin/
ENV LANG=en_US.utf8 HOME=/addon ADDON=/addon MAVEN_OPTS="-Xmx1g" GOTOOLCHAIN=local GOFLAGS=-mod=mod
WORKDIR /addon
USER 1001
ENTRYPOINT ["/usr/bin/cve-remediation"]
