#!/usr/bin/env python3
"""Write independently authenticated factory media to an explicitly selected USB disk."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from lanrith import media, release
from lanrith.factory import eligible


def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('release',type=Path)
    parser.add_argument('--certificate',type=Path,required=True)
    parser.add_argument('--image-id', default='lanrith')
    parser.add_argument('--target',type=Path,required=True)
    parser.add_argument('--verify-only',action='store_true',help='Verify existing media without writing it')
    args=parser.parse_args()
    root=args.release.resolve()
    release.require(os.geteuid()==0, 'Media writing requires root.')
    release.require(re.fullmatch(r'/[A-Za-z0-9_./+-]+',str(root)) and
                    re.fullmatch(r'/dev/disk/by-id/[A-Za-z0-9_.:+-]+',str(args.target)),
                    'Use a canonical release directory and a stable target identity.')
    release.require(args.certificate.resolve().parent != root, 'Supply controller trust independently of the release.')
    manifest=release.verify(root,args.certificate,purpose='factory',image_id=args.image_id)
    image=root/next(a['name'] for a in manifest['artifacts'] if a['role']=='disk')
    minimum=image.stat().st_size+sum(a['size'] for a in manifest['artifacts'])+256*1024*1024
    target=str(args.target.resolve())
    def inspect():
        rows=json.loads(run('lsblk','--json','--bytes','--paths','--output',
                            'NAME,TYPE,SIZE,RO,LOG-SEC,MOUNTPOINTS,TRAN,FSTYPE,UUID',target).stdout)['blockdevices']
        release.require(len(rows)==1 and rows[0].get('tran')=='usb' and eligible(rows[0],'',minimum),
                        'USB target is mounted, in use, incompatible, read-only or too small.')
        mounted=json.loads(run('findmnt','--json','--output','UUID').stdout)
        uuids=set()
        pending=list(mounted.get('filesystems',[]))
        while pending:
            row=pending.pop();pending.extend(row.get('children',[]))
            if row.get('uuid'): uuids.add(row['uuid'])
        pending=list(rows)
        while pending:
            row=pending.pop();pending.extend(row.get('children',[]))
            release.require(row.get('fstype')!='zfs_member' and not (row.get('uuid') and row['uuid'] in uuids),
                            'Target belongs to an active filesystem or a storage pool.')
    inspect()
    if args.verify_only:
        media.verify(target,root,args.certificate,manifest)
        print('Factory partitions and the complete signed media payload passed read-back verification.')
        return
    release.require(input('Type ERASE-AND-WRITE '+str(args.target)+' to continue: ').strip()==
                    'ERASE-AND-WRITE '+str(args.target),'Destructive media writing was not confirmed.')
    release.require(str(args.target.resolve())==target,'USB identity changed before writing.')
    inspect()
    run('dd','if='+str(image),'of='+target,'bs=4M','conv=fsync','status=progress')
    run('cmp','--bytes='+str(image.stat().st_size),str(image),target)
    run('sfdisk','--relocate','gpt-bak-std',target)
    with tempfile.TemporaryDirectory(prefix='lanrith-media.') as temporary:
        definition=Path(temporary)/'90-media.conf'
        size=sum(a['size'] for a in manifest['artifacts'])+128*1024*1024
        definition.write_text('[Partition]\nType=linux-generic\nLabel=lanrith-factory-media\nFormat=ext4\n'
                              f'SizeMinBytes={size}\nSizeMaxBytes={size}\nCopyFiles={root}:/release\n')
        run('systemd-repart','--definitions='+temporary,'--empty=allow','--dry-run=no','--seed=random',target)
    run('sync')
    run('udevadm','settle')
    release.require(str(args.target.resolve())==target,'USB identity changed during media creation.')
    media.verify(target,root,args.certificate,manifest)
    print('Factory partitions and the complete signed media payload passed read-back verification.')


if __name__=='__main__':
    try:
        main()
    except (release.ReleaseError,OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        raise SystemExit(str(error) if isinstance(error,release.ReleaseError) else 'Factory media creation failed closed.')
