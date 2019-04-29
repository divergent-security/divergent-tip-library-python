FROM alpine:latest
RUN apk update
RUN apk add --no-cache python py-pip
RUN pip install netaddr
RUN apk del --no-cache py-pip

WORKDIR /worker
COPY divergent_tip_library/__init__.py     divergent_tip_library/__init__.py
COPY divergent_tip_library/constants.py     divergent_tip_library/constants.py
COPY divergent_tip_library/job_template.py divergent_tip_library/job_template.py
COPY divergent_tip_library/setup.py        divergent_tip_library/setup.py

EXPOSE 65050/tcp
