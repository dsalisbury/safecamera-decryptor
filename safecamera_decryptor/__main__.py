from argparse import ArgumentParser
import os
import os.path

from .decrypt import Decryptor, FileContentProvider, FilenameProvider


def build_parser():
    default_jobs = 1

    parser = ArgumentParser()
    parser.add_argument('--pwfile', required=True, help='Master password file')
    parser.add_argument('--outdir', default='.',
                        help=('Output directory for decrypted files [default '
                              '%(default)r]'))
    parser.add_argument('files', metavar='file', nargs='+',
                        help='File(s) to decrypt')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    with open(args.pwfile) as f:
        master_password = f.read()
    decryptor = Decryptor(master_password=master_password)
    for path in args.files:
        print(path)
        filename = b''.join(decryptor.decrypt(FilenameProvider(path=path)))
        target = os.path.join(outdir, filename.decode())
        with open(target, 'wb') as f:
            for chunk in decryptor.decrypt(FileContentProvider(path=path)):
                f.write(chunk)
