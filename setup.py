# setup.py
from setuptools import setup, find_packages

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
    version='2.0.2',

    # Autor e email
    author='Spectra Team',
    author_email='',

    # Breve descrição
    description='Spectra - Web Security Suite - Uma ferramenta de hacking ético para análise de segurança web.',

    # Descrição longa (do README)
    long_description=long_description,
    long_description_content_type='text/markdown',

    # Usa find_packages para descobrir automaticamente os módulos
    packages=find_packages(),

    # Lista de dependências necessárias
    install_requires=required,

    # O entry_point agora aponta para a estrutura modular
    entry_points={
        'console_scripts': [
            'spectra = spectra.cli.main:main',
        ],
    },

    # Classificadores para ajudar a descrever seu pacote
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Environment :: Console',
        'Topic :: Security',
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security :: Cryptography',
        'Topic :: Internet :: WWW/HTTP',
    ],
    python_requires='>=3.11',
    
    # Inclui arquivos adicionais
    include_package_data=True,
    package_data={
        'spectra': ['*.txt', '*.md'],
    },
    
    # Keywords para busca
    keywords='security, web, hacking, penetration testing, vulnerability scanner',
    
    # URL do projeto
    url='https://github.com/spectra-team/spectra',
)
