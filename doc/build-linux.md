Building on Linux
===============

To install the required dependencies, run the following command:

$ sudo apt-get install git-core build-essential libssl-dev libboost-all-dev libdb5.1-dev libdb5.1++-dev libgtk2.0-dev libminiupnpc-dev qt4-qmake mingw32 synaptic qt-sdk qt4-dev-tools libqt4-dev libqt4-core libqt4-gui libdb++-dev miniupnpc

Then grab the latest version of the MaxCoin source code from Github

$ git clone https://github.com/Max-Coin/MaxCoin.git

To build the daemon, run the following commands

$ cd maxcoin/src

$ make -f makefile.unix

Optionally, debugging symbols can be removed from the binary to reduce it's size. This can be done using strip.

$ strip maxcoind

Then, to build the GUI, run the following commands:

$ cd ..

$ qmake

$ make

Troubleshooting:
-------------

Building miniupnpc
----------------

If your OS doesn't support libminiupnpc, you can build this manually by performing the following steps:

$ wget 'http://m