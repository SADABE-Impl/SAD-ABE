# SAD-ABE
(Switchable-attribute delegatable) ABE implementation

## Prerequisites

The schemes have been tested with Charm 0.50 and Python 3.8.10.
Charm 0.50 can be installed from [this](https://github.com/JHUISI/charm.git) page, or by running
```sh
pip install -r requirements.txt
```
Once you have Charm, you can run
```sh
sudo make && sudo pip install . && python test/main.py
```
to test the schemes. 

You can run 
```sh
sudo make && sudo pip install . && python benchmark/benchmark_XXX.py enc/keygen/dec
```
to run the benchmarks.
