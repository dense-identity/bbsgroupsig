sudo rm -rf build
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
sudo cmake --build . --target install
sudo ldconfig
