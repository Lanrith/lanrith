#!/usr/bin/env python3
"""Check read-only Q35 hotplug support using only a disposable regular file."""

import json
import os
import socket
import subprocess
import tempfile
import time


def main():
    with tempfile.TemporaryDirectory(prefix='lanrith-hotplug-smoke-') as directory:
        qmp = directory+'/qmp'
        disk = directory+'/disk.raw'
        with open(disk, 'wb') as stream:
            stream.truncate(1024*1024)
        process = subprocess.Popen(['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-nodefaults',
            '-display', 'none', '-S', '-qmp', 'unix:'+qmp+',server=on,wait=off',
            '-device', 'pcie-root-port,id=lanrith-hotplug-port,chassis=1'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic()+15
            while not os.path.exists(qmp) and time.monotonic() < deadline:
                time.sleep(0.1)
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(10)
                client.connect(qmp)
                with client.makefile('rwb', buffering=0) as stream:
                    json.loads(stream.readline())
                    def call(name, arguments=None):
                        request = {'execute': name}
                        if arguments is not None:
                            request['arguments'] = arguments
                        stream.write(json.dumps(request).encode()+b'\n')
                        while True:
                            result = json.loads(stream.readline())
                            if 'error' in result:
                                raise RuntimeError('Synthetic QEMU hotplug rejected.')
                            if 'return' in result:
                                return
                    call('qmp_capabilities')
                    call('blockdev-add', {'node-name': 'test-file', 'driver': 'file',
                                          'filename': disk, 'read-only': True})
                    call('blockdev-add', {'node-name': 'test-raw', 'driver': 'raw',
                                          'file': 'test-file', 'read-only': True})
                    call('device_add', {'driver': 'virtio-blk-pci', 'id': 'test-device',
                                        'drive': 'test-raw', 'serial': 'lanrith-readback',
                                        'bus': 'lanrith-hotplug-port'})
            print(json.dumps({'schema': 1, 'scope': 'synthetic-q35-hotplug-only', 'result': 'pass'}))
        finally:
            process.terminate()
            process.wait(timeout=10)


if __name__ == '__main__':
    main()
