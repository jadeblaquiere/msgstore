# msgstore

Msgstore is a distributed message storage service for the ciphrtxt protocol. Msgstore instances are designed to work in conjunction with ctcd, the cryptocurrency-based token service for ciphrtxt. 

Running a msgstore node is relatively straightforward: 

1. Install leveldb
```
# for ubuntu 14:
sudo apt-get install libleveldb1 libleveldb-dev

# for ubuntu 16:
sudo apt-get install libleveldb1v5 libleveldb-dev

# for rh-based distro (e.g. CentOS):
yum install -y leveldb leveldb-devel 

# for OS X
brew install leveldb
```
1. Clone msgstore
```
git clone https://github.com/jadeblaquiere/msgstore.git
```
1. Install python dependencies (NOTE: msgstore is tested with python 3.5 - if your system python is 2.x you should probably use pyenv to set python preference for the local directory)
```
cd msgstore
pip install -r requirements.txt
```
1. Ensure your network and host are configured to allow incoming connections on ports 7764 (ctcd) and 7754 (msgstore) from your external network hostname/address (which you will need)
1. (optional) Obtain a Network Access Key (NAK) to support onion routing connecitons... if you don't have one yet you can leave off the --nakpriv option
1. Start msgstore (with your own username, password)
```
python3 ./app.py --rpcuser=[USERNAME] --rpcpass=[PASSWORD] --exthost=[EXTERNAL HOSTNAME] --nakpriv=[NAK PRIVATE KEY]
```
1. Install and bootstrap your ctcd instance. See [ctcd page on github](https://github.com/jadeblaquiere/ctcd) for more information
1. Start ctcd (with your own username, password)
```
ctcd --nodnsseed --txindex --rpcuser=[USERNAME] --rpcpass=[PASSWORD] --addpeer ciphrtxt.com
```
