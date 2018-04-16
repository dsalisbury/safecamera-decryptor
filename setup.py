from setuptools import find_packages, setup


setup(
    name='safecamera-decryptor',
    description='Python-based decryptor for files encrypted with SafeCamera',
    license='MIT',
    url='https://github.com/dsalisbury/safecamera-decryptor',

    version='0.0.1',
    packages=find_packages(),

    author='Dave Salisbury',
    author_email='safecamera-decryptor@dsalisbury.to',

    install_requires=(
        'cryptography',
        'jasypt4py',
        'pycrypto',
    ),

    entry_points={
        'console_scripts': [
            'safecamera-decryptor = safecamera_decryptor.__main__:main'
        ],
    },
)
