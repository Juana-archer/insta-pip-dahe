from setuptools import setup, find_packages

setup(
    name="insta-dahe",
    version="1.0.0",
    author="Juana Archer",
    author_email="faniry1d@gmail.com",
    description="Un package Python pour...",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Juana-archer/insta-kendou",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        # Ajoutez vos dépendances ici
        # "requests",
        # "beautifulsoup4",
    ],
)
