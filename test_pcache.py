from peercache import PeerHost, PeerCache
import time
import tornado.ioloop

test_peers = ['ciphrtxt.com:5000',
              'coopr8.com:5000',
              'indigo.bounceme.net:5000']

print('\n')
print('test PeerHost')
for t in test_peers:
    s = t.split(':')
    p = PeerHost(s[0], s[1])
    print('Peer imported as : ' + str(p))
    if not p.refresh():
        print('failed to refresh ' + str(p.host))
    print('Peer updated to : ' + str(p))
    jp = p.dumpjson()
    print('Peer json = ' + str(jp))
    np = PeerHost.loadjson(jp)
    print('Reloaded as : ' + str(np))

print('\n')
print('test PeerCache')
pc = PeerCache('localhost', 5000)
print('refreshing')
pc.refresh()
l = pc.list_peers()
print('peer list = ' + str(l))
print('discovering')
pc.discover_peers()
l = pc.list_peers()
print('peer list = ' + str(l))

print('all tests complete!')
tornado.ioloop.IOLoop.instance().start()