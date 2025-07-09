rm -rf bbuild
mkdir -p bbuild && cd bbuild
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --target install
ldconfig
rm -rf bbuild