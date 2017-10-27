#!/bin/bash
cd ../lite-userspace ; make clean ; make all -j 24; cd ../core
#cd test ; make ; cd ..
make
insmod lite_internal.ko
insmod lite_api.ko
#insmod lite_test.ko
