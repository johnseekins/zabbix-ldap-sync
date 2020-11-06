
from setuptools import setup

setup(
    name="zabbix_ldap_sync",
    version="0.1",
    description="Imports users and groups from LDAP into Zabbix",
    url="https://github.com/datto-aparrill/zabbix-ldap-sync",
    author="Marc Schöchlin, Alex Parrill",
    author_email="ms@256bit.org, aparrill@datto.com",
    license="BSD 3-Clause License",
    packages=["zabbix_ldap_sync"],
    zip_safe=False,
    entry_points={
        "console_scripts": ["zabbix-ldap-sync=zabbix_ldap_sync.__main__:main"]
    },
    install_requires=[
        "pyldap",
        "pyzabbix",
    ]
)
