# setup.py
from setuptools import setup

# Lê as dependências do requirements.txt
with open('requirements.txt') as f:
    required = f.read().splitlines()

# Lê o conteúdo do README.md para a descrição longa
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    # Nome do seu pacote
    name='spectra-suite',

    # Versão do seu pacote
    version='2.8',

    # Autor e email
    author='Seu Nome',
    author_email='seu.email@example.com',

    # Breve descrição
    description='Spectra - Uma ferramenta de hacking ético para análise de segurança web.',

    # Descrição longa (do README)
    long_description=long_description,
    long_description_content_type='text/markdown',

    # Em vez de 'packages', usamos 'py_modules' para um único arquivo Python
    py_modules=['spectra'],

    # Lista de dependências necessárias
    install_requires=required,

    # O entry_point agora aponta diretamente para o módulo
    entry_points={
        'console_scripts': [
            'spectra = spectra:main',
        ],
    },

    # Classificadores para ajudar a descrever seu pacote
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License', # Ou a licença que você preferir
        'Operating System :: OS Independent',
        'Environment :: Console',
        'Topic :: Security',
    ],
    python_requires='>=3.6',
)
