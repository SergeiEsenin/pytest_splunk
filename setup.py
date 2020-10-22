from setuptools import setup

setup(
    name='pytest_splunkHEC',
    version='0.1.8',
    author='S Pavliuk',
    license='proprietary',
    py_modules=['pytest_splunkHEC'],
    install_requires=['pytest'],
    entry_points={'pytest11': ['splunkHEC = pytest_splunkHEC', ], },
)
