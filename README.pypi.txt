https://packaging.python.org/tutorials/packaging-projects/

#! change version in setup.cfg

# build archive under dist/
python -m build

# upload build archive
python -m twine upload dist/*

# test virtual environment
mkdir test
cd test
python -m venv venv
source venv/bin/activate

pip install lc7001
pip install cryptography==3.3.2

python ../cli.py
