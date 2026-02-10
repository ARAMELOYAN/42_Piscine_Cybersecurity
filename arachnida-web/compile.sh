#!/bin/bash

g++ -std=c++17 -O2 -Wall -Wextra scorpion.cpp -lexiv2 -o scorpion_cpp
gcc -std=c17 -O2 -Wall -Wextra scorpion.c $(pkg-config --cflags --libs gexiv2) -o scorpion_c                                                                                                                                  
gcc -std=c17 -O2 -Wall -Wextra spider.c -lcurl -o spider_c
g++ -std=c++17 -O2 -Wall -Wextra spider.cpp -lcurl -o spider_cpp
