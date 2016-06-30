# msgstore

Msgstore is a distributed message storage service for the ciphrtxt protocol. Msgstore instances are designed to work in conjunction with ctcd, the cryptocurrency-based token service for ciphrtxt. 

Running a msgstore node is relatively straightforward: 

1. Install and bootstrap your ctcd instance. See [ctcd page on github](https://github.com/jadeblaquiere/ctcd) for more information
1. Clone msgstore
```
git clone https://github.com/jadeblaquiere/msgstore.git
```
1. Install leveldb
```
# for ubuntu:
sudo apt-get install libleveldb1 libleveldb-dev

# for OS X
brew install leveldb
```
1. Install python dependencies (NOTE: msgstore is tested with python 3.5.1 - if your system python is 2.x you should probably use pyenv to set python preference for the local directory)
```
pip3 install tornado requests requests_futures plyvel pycrypto
pip3 install git+https://github.com/jadeblaquiere/ecpy.git
pip3 install git+https://github.com/jadeblaquiere/python-ctcoinlib.git
```
1. create the messages and recv directories
```
cd msgstore
mkdir messages
mkdir recv
```
1. Ensure your network and host are configured to allow incoming connections on ports 7764 (ctcd) and 5000 (msgstore) from your external network hostname/address (which you will need)
1. Obtain a Network Access Key (NAK) to support onion routing connecitons
1. Start ctcd (with your own username, password)
```
ctcd --nodnsseed --txindex --rpcuser=[USERNAME] --rpcpass=[PASSWORD] --addpeer ciphrtxt.com
```
1. Start msgstore (using the same RPC username and password)
```
python3 ./app.py --rpcuser=[USERNAME] --rpcpass=[PASSWORD] --exthost=[EXTERNAL HOSTNAME] --nakpriv=[NAK PRIVATE KEY]
```
