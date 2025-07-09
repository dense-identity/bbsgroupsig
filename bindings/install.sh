rm -rf bbuild
mkdir -p bbuild && cd bbuild
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release ..
sudo cmake --build . --target install
sudo ldconfig
rm -rf bbuild