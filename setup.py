#!/usr/bin/env python

from os import path
from setuptools import find_packages, setup

wd = path.abspath(path.dirname(__file__))
with open(path.join(wd, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    description='A tool to manage contents of AWS SSM Parameter Store',
    name='ssm-diff',
    version='0.5.5',
    author='Sergey Motovilovets',
    author_email='motovilovets.sergey@gmail.com',
    license='MIT',
    url='https://github.com/runtheops/ssm-diff',
    download_url='https://github.com/runtheops/ssm-diff/archive/0.5.tar.gz',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords=['aws', 'ssm', 'parameter-store'],
    packages=find_packages(),
    scripts=[],
    entry_points={'console_scripts': ['ssm-diff=ssmdiff.main:main']},
    install_requires=[
        'termcolor',
        'boto3',
        'dpath',
        'PyYAML'
    ]
)
