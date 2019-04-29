FROM alpine:latest
RUN apk update && \
	apk add --no-cache python py-pip git && \
	pip install netaddr && \
	pip install git+https://github.com/divergent-security/divergent-tip-library-python.git && \
	apk del --no-cache py-pip

# WORKDIR /worker

#EXPOSE 65050/tcp
