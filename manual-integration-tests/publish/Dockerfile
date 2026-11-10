FROM public.ecr.aws/docker/library/ubuntu:resolute

RUN set -x \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openjdk-17-jdk-headless \
    python3 \
    npm \
 && apt-get clean autoclean \
 && apt-get autoremove --yes \
 && rm -rf /var/lib/{apt,dpkg,cache,log}/

COPY --chmod=0755 build-and-publish.sh /code/build-and-publish.sh
# One COPY per project: a multi-source COPY merges the directories' contents
# into /code instead of keeping each directory.
COPY maven-echo-v1/ /code/maven-echo-v1/
COPY pypi-echo/ /code/pypi-echo/
COPY npm-echo/ /code/npm-echo/

WORKDIR /code

# You need to mount the `manual-integration-tests/setup`
# directory to this container's `/server-setup` directory.
VOLUME [ "/server-setup" ]
ENV SERVER_SETTINGS_DIR=/server-setup

ENTRYPOINT [ "/code/build-and-publish.sh" ]
