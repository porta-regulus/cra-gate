# The cra-gate CLI as an image, for Jenkins, Azure DevOps and any other runner.
#   docker run --rm -e CVD_API_KEY -e CVD_PRODUCT_ID -v "$PWD:/work" -w /work <image> run --sbom sbom.cdx.json
FROM node:22-alpine
COPY cra-gate.mjs /opt/cra-gate/cra-gate.mjs
USER node
ENTRYPOINT ["node", "/opt/cra-gate/cra-gate.mjs"]
