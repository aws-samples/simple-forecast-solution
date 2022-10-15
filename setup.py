import setuptools

setuptools.setup(
    name="afa",
    version="0.2.0",
    packages=["afa"],
    install_requires=[
        "statsmodels>=0.12.2",
        "pandas>=1.2.4",
        "numpy==1.23.3",
        "scipy>=1.6.0",
        "tqdm",
        "streamlit",
        "stqdm",
        "cloudpickle==1.6.0",
        "plotly",
        "awswrangler",
        "sspipe",
        "humanfriendly",
        "streamlit-aggrid",
        "joblib",
        "toolz",
        "pandera",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3.8" "Programming Language :: Python :: 3.9"
    ],
)
