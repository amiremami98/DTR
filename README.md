First, Install libncurses:
```
sudo apt update
sudo apt install gcc libncurses-dev
```

Then Compile it
```
gcc -O2 -Wall -Wextra -Wpedantic dtr.c -o dtr -lncurses -lm
```
