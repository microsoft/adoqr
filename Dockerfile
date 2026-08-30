# adoqr — Azure DevOps Quick Review
#
# Usage:
#   docker run --rm \
#     -v $(pwd)/reports:/reports \
#     -v $HOME/.azure:/root/.azure \
#     ghcr.io/microsoft/adoqr:latest \
#     -Organization MyOrg -OutputFormat all
#
# Reports are written to /reports by default via the ADOQR_OUTPUT_PATH env var
# set below, which is exposed as a volume — bind-mount a host path to keep them
# after the container exits. Pass -OutputPath to override the destination.
#
# To authenticate non-interactively, mount your existing Azure CLI profile
# (~/.azure) into the container as shown above, or run `az login` inside the
# container interactively first.

FROM mcr.microsoft.com/powershell:lts-debian-12

LABEL org.opencontainers.image.title="adoqr" \
      org.opencontainers.image.description="Azure DevOps Quick Review — best-practice assessment for ADO orgs and projects" \
      org.opencontainers.image.source="https://github.com/microsoft/adoqr" \
      org.opencontainers.image.licenses="MIT"

# Install Azure CLI + the azure-devops extension
# https://learn.microsoft.com/cli/azure/install-azure-cli-linux?pivots=apt
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        apt-transport-https \
    && mkdir -p /etc/apt/keyrings \
    && curl -sLS https://packages.microsoft.com/keys/microsoft.asc \
       | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg \
    && chmod go+r /etc/apt/keyrings/microsoft.gpg \
    && AZ_DIST="$(lsb_release -cs)" \
    && printf 'Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\nSuites: %s\nComponents: main\nArchitectures: amd64 arm64\nSigned-by: /etc/apt/keyrings/microsoft.gpg\n' "$AZ_DIST" \
       > /etc/apt/sources.list.d/azure-cli.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends azure-cli \
    && rm -rf /var/lib/apt/lists/* \
    && az extension add --name azure-devops --only-show-errors

# Bring in adoqr
WORKDIR /opt/adoqr
COPY invoke-adoqr.ps1 /opt/adoqr/
COPY remediation-steps.psd1 /opt/adoqr/
COPY schemas /opt/adoqr/schemas

# Default output directory; callers should bind-mount a host path here
VOLUME ["/reports"]
ENV ADOQR_OUTPUT_PATH=/reports

# Use pwsh as the entry-point so callers pass adoqr flags directly
ENTRYPOINT ["pwsh", "-NoProfile", "-File", "/opt/adoqr/invoke-adoqr.ps1"]
CMD ["-?"]
