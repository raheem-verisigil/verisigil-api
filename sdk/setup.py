from setuptools import setup, find_packages

setup(
    name="verisigil",
    version="1.0.0",
    description="Constitutional Gateway SDK — Issue → Verify → Prove",
    long_description="VeriSigil AI is constitutional runtime infrastructure for autonomous AI systems. Intelligence scales. Legitimacy is verified.",
    author="Raheem Larry Babatunde",
    author_email="raheem@verisigilai.com",
    url="https://verisigilai.com",
    packages=find_packages(),
    install_requires=["httpx>=0.24.0"],
    python_requires=">=3.9",
    entry_points={"console_scripts": ["verisigil=verisigil.demo:main"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    keywords="AI governance constitutional execution admissibility EU-AI-Act runtime",
)
