from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pq-vpn",
    version="1.0.0",
    author="PQ-VPN Team",
    author_email="pqvpn@example.com",
    description="A Python-based custom VPN system using post-quantum cryptography",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pqvpn/pq-vpn",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.14.1",
        "flask>=2.0.0",
        "pywin32>=300;platform_system=='Windows'",
    ],
    entry_points={
        'console_scripts': [
            'pqvpn-server=main:server_main',
            'pqvpn-client=main:client_main',
            'pqvpn-web=main:web_main',
        ],
    },
    include_package_data=True,
)
