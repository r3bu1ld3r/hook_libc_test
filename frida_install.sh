#!/bin/bash

mkdir /tmp/frida-libs
cd /tmp/frida-libs

wget https://github.com/frida/frida/releases/download/16.0.1/frida-core-devkit-16.0.1-linux-x86_64.tar.xz -O core-16.0.1.tar.xz
wget https://github.com/frida/frida/releases/download/16.0.1/frida-gum-devkit-16.0.1-linux-x86_64.tar.xz -O gum-16.0.1.tar.xz

tar xf ./core-16.0.1.tar.xz
tar xf ./gum-16.0.1.tar.xz

cp -v *.h /usr/local/include
cp -v *.a /usr/local/libs

cd ~
rm -rf /tmp/frida-libs
