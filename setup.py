from setuptools import find_packages, setup

setup(
    name="infino-sdk",
    version="0.3.0",
    description="Python SDK for Infino API",
    author="Infino AI, Inc.",
    author_email="support@infino.ai",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "backoff>=2.0.0",
        "websockets>=10.0",
        "PyYAML>=6.0",
    ],
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
