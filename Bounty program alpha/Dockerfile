FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive
ENV LC_CTYPE=C.UTF-8

RUN useradd -ms /bin/bash bounty_program
WORKDIR /home/bounty_program

# RUN dpkg --add-architecture i386
RUN apt-get update --fix-missing -y

RUN apt-get install -y apt-utils software-properties-common

RUN apt-get install -y build-essential \
        socat \
        netcat 

ADD ./libc.so.6 /lib/x86_64-linux-gnu/
ADD ./bounty_program /home/bounty_program
ADD ./flag /home/bounty_program
ADD ./wrapper /home/bounty_program


ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/bounty_program/wrapper,stderr"]
EXPOSE 1337

