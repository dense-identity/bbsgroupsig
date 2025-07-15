rm -rf buildb
mkdir -p buildb && cd buildb
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release ..
sudo cmake --build . --target install
sudo ldconfig
rm -rf buildb