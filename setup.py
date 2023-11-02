import pathlib

from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()


setup(
    name="IoctlHunter",
    version="0.2",
    description="CLI tools allowing to ease the dynamic analysis of IOCTL calls in destination to Windows drivers for RedTeam/pentest perspectives",
    long_description=README,
    long_description_content_type="text/markdown",
    license="MIT",
    author="Zak",
    python_requires=">=3.6",
    packages=find_packages(),
    install_requires=[
        "colorama",
        "frida-tools",
        "psutil",
    ],
    entry_points={
        "console_scripts": [
            "IoctlHunter = ioctl_hunter.ui.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
