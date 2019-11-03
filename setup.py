from setuptools import setup, find_packages

from b2_storage import __version__

version_str = ".".join(str(n) for n in __version__)

setup(
    name="django-backblazeb2-storage",
    version=version_str,
    license="BSD",
    description="Django BackBlaze B2 Storage",
    author="Royendgel Silberie",
    author_email="rsilberie@techprocur.com",
    url="https://github.com/royendgel/django-blackblazeb2-storage",
    packages=find_packages(),
    install_requires=[
        'Django>=1.11',
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Framework :: Django",
    ],
)
