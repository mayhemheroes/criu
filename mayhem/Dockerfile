FROM ubuntu:22.04 as builder
ARG CC=gcc

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
	$CC \
	bash \
	build-essential \
	coreutils \
	procps \
	git \
	gnutls-dev \
	libaio-dev \
	libcap-dev \
	libnet-dev \
	pkg-config \
	python3 \
	sudo \
	clang libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler python3-protobuf python3-future libnl-3-dev libcap-dev
COPY . /criu
WORKDIR /criu
RUN make mrproper && date && make -j $(nproc) CC="$CC" && date
RUN clang++ /criu/mayhem/fuzz_criu_set_parent_images.cpp -fsanitize=fuzzer,address /criu/lib/c/libcriu.a -lprotobuf-c -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libprotobuf-c-dev
COPY --from=builder /criu/compel/compel-host-bin /
COPY --from=builder /fuzz /fuzz_criu_set_parent_images
