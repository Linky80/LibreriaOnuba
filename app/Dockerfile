FROM python:3.11-alpine as builder
RUN apk --update add bash nano g++
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install -r requirements.txt

# Build a fresh container, copying across files & compiled parts
FROM python:3.11-alpine
COPY . /app
WORKDIR /app
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin /usr/local/bin
ENV tokentimetolive=60

ENTRYPOINT ["python"]
CMD ["app.py"]
