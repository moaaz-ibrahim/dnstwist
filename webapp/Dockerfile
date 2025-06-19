# Execute the following command to build the image: tar -czh . | docker build -t dnstwist_webapp -

FROM python:3.11-slim
MAINTAINER marcin@ulikowski.pl

WORKDIR    /opt/dnstwist

COPY       webapp/webapp.py /opt/dnstwist/webapp.py
COPY       webapp/webapp.html /opt/dnstwist/webapp.html
COPY       ../dnstwist.py /opt/dnstwist/

RUN        pip install flask gunicorn dnspython geoip2 tld idna python-whois

EXPOSE     8000

CMD        ["gunicorn", "webapp:app", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "3", "--log-level", "debug"]
