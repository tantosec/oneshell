FROM ubuntu:latest

RUN apt-get update && apt-get install -y nasm gcc golang
RUN mkdir /.cache && chmod -R 777 /.cache