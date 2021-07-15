FROM tleavy/android-sdk-ndk:api28ndk20

ADD . /usr/share/wickr-crypto-c
WORKDIR /usr/share/wickr-crypto-c

RUN apt -qq update
RUN apt -qq -y install curl git build-essential autoconf automake cmake bison libpcre3-dev > /dev/null
RUN git clone https://github.com/swig/swig.git && cd swig && git checkout rel-4.0.0 && ./autogen.sh && ./configure && make -j8 && make install
RUN wget -q https://golang.org/dl/go1.16.6.linux-amd64.tar.gz && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.6.linux-amd64.tar.gz

# https://github.com/WickrInc/wickr-crypto-c/blob/aws-lc/docker/android-fips/Dockerfile

# FIPS can only build with Android NDK r15 and lower
#RUN wget -q https://dl.google.com/android/repository/android-ndk-r15c-linux-x86_64.zip
#RUN unzip -q android-ndk-r15c-linux-x86_64.zip -d /usr/opt/android && rm android-ndk-r15c-linux-x86_64.zip

#ENV ANDROID_NDK_HOME ${ANDROID_HOME}/android-ndk-r15c
ENV PATH $PATH:/usr/local/go/bin

RUN go env -w GOPROXY=direct
