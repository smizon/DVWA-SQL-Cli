from setuptools import setup

setup(
    name="SQLInjectionDetectionTest",
    version='0.1.0',
    py_modules=['init'],
    install_requires=[
        'Click',
        'clint'
    ],
    entry_points='''
        [console_scripts]
        scan-sql=init:main
    ''',
)