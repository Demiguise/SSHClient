#!/bin/sh
cmake -G Ninja -Bbld -H. -DCMAKE_BUILD_TYPE=Debug -DSSH_Target_Platform=Linux
