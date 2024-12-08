from setuptools import setup, find_packages
import pathlib

HERE = pathlib.Path(__file__).parent.resolve()

README = (HERE / "README.md").read_text(encoding="utf-8") if (HERE / "README.md").exists() else ""

setup(
    name="deauth-backend-python",
    version="0.1.0",
    author="pr-citrate",
    author_email="pr.citrate@gmail.com",
    description="A FastAPI backend for deauth packet detection",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/JBSH-34/deauth-backend-python",
    py_modules=["main"],
    classifiers=[
        "Programming Language :: Python :: 3.13",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.13',
    install_requires=[
        "fastapi>=0.115.0",
        "uvicorn[standard]>=0.32.0",
        "scapy>=2.6.0",
        "prisma>=0.15.0",
        "pydantic>=2.9.0",
        "icecream>=2.1.1",
    ],
    include_package_data=True
)
